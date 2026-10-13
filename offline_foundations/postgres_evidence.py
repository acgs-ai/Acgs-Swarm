"""Optional real PostgreSQL storage for the separate T6 evidence contract.

Selection rules remain in evidence.py. This adapter owns only its explicit t6_
schema, never an authority store. A trusted database owner can still alter DDL;
append-only triggers protect ordinary data mutations, not administrative access.
"""

import base64
import hashlib
import re
from contextlib import contextmanager

import psycopg2
from psycopg2 import extensions, sql
from psycopg2.extras import DictCursor

from .evidence import EvidenceError, EvidenceStore

_TEXT_TAG = "\x1eT6:"


def _encode(value):
    # PostgreSQL TEXT excludes NUL; SQLite accepts it in bounded identities.
    # Escape only those strings, plus the reserved prefix to avoid collisions.
    if isinstance(value, str) and ("\0" in value or value.startswith(_TEXT_TAG)):
        return _TEXT_TAG + base64.b64encode(value.encode()).decode("ascii")
    return value


def _decode(value):
    if isinstance(value, memoryview):
        return bytes(value)
    if isinstance(value, str) and value.startswith(_TEXT_TAG):
        return base64.b64decode(value[len(_TEXT_TAG) :], validate=True).decode()
    return value


class _Cursor:
    def __init__(self, cursor):
        self.cursor = cursor

    def fetchone(self):
        row = self.cursor.fetchone()
        if row is not None:
            for index, value in enumerate(row):
                row[index] = _decode(value)
        return row

    def __iter__(self):
        while (row := self.fetchone()) is not None:
            yield row


class _Connection:
    """Narrow bridge for the fixed statements used by the shared evidence rules."""

    def __init__(self, connection):
        self.connection = connection

    def execute(self, statement, parameters=()):
        if statement == "INSERT OR IGNORE INTO blobs VALUES(?,?,?)":
            statement = "INSERT INTO blobs(scope_key,digest,bytes) VALUES(?,?,?) ON CONFLICT DO NOTHING"
        elif statement.startswith("INSERT INTO revisions VALUES"):
            statement = statement.replace(
                "INSERT INTO revisions VALUES",
                "INSERT INTO revisions(scope_key,evidence_id,source_key,revision_order,"
                "claim_key,claim_type,observed,valid_from,valid_to,body,digest) VALUES",
            )
        elif statement.startswith("INSERT INTO events VALUES"):
            statement = statement.replace(
                "INSERT INTO events VALUES",
                "INSERT INTO events(scope_key,event_id,kind,target,observed,effective,body,digest) VALUES",
            )
        if "scope_key=?" in statement:
            # Bounded index key plus the full scope predicate: a hash collision
            # must fail admission or lookup closed, never cross a scope boundary.
            statement = statement.replace(
                "scope_key=?",
                "scope_hash=sha256(convert_to(?,'UTF8')) AND scope_key=?",
            )
            parameters = (parameters[0], parameters[0], *parameters[1:])
        cursor = self.connection.cursor(cursor_factory=DictCursor)
        cursor.execute(statement.replace("?", "%s"), tuple(map(_encode, parameters)))
        return _Cursor(cursor)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS revisions (
 scope_key TEXT NOT NULL,evidence_id TEXT NOT NULL,source_key TEXT NOT NULL,
 revision_order BIGINT NOT NULL,claim_key TEXT NOT NULL,claim_type TEXT NOT NULL,
 observed BIGINT NOT NULL,valid_from BIGINT NOT NULL,valid_to BIGINT,
 body TEXT NOT NULL,digest TEXT NOT NULL,
 scope_hash BYTEA NOT NULL,evidence_hash BYTEA NOT NULL,claim_hash BYTEA NOT NULL,
 PRIMARY KEY(scope_hash,evidence_hash));
CREATE INDEX IF NOT EXISTS evidence_claim_scope
 ON revisions(scope_hash,claim_hash,claim_type,observed);
CREATE TABLE IF NOT EXISTS blobs (
 scope_key TEXT NOT NULL,digest TEXT NOT NULL,bytes BYTEA NOT NULL,
 scope_hash BYTEA NOT NULL,PRIMARY KEY(scope_hash,digest));
CREATE TABLE IF NOT EXISTS events (
 scope_key TEXT NOT NULL,event_id TEXT NOT NULL,kind TEXT NOT NULL,target TEXT NOT NULL,
 observed BIGINT NOT NULL,effective BIGINT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,
 scope_hash BYTEA NOT NULL,event_hash BYTEA NOT NULL,PRIMARY KEY(scope_hash,event_hash));
CREATE OR REPLACE FUNCTION prepare_evidence_keys() RETURNS trigger
 LANGUAGE plpgsql AS $$
 BEGIN
   NEW.scope_hash := pg_catalog.sha256(pg_catalog.convert_to(NEW.scope_key,'UTF8'));
   IF TG_TABLE_NAME='revisions' THEN
     NEW.evidence_hash := pg_catalog.sha256(pg_catalog.convert_to(NEW.evidence_id,'UTF8'));
     NEW.claim_hash := pg_catalog.sha256(pg_catalog.convert_to(NEW.claim_key,'UTF8'));
   ELSIF TG_TABLE_NAME='events' THEN
     NEW.event_hash := pg_catalog.sha256(pg_catalog.convert_to(NEW.event_id,'UTF8'));
   END IF;
   RETURN NEW;
 END; $$;
CREATE OR REPLACE FUNCTION reject_evidence_mutation() RETURNS trigger
 LANGUAGE plpgsql AS $$
 BEGIN RAISE EXCEPTION 'append-only' USING ERRCODE='23514'; END; $$;
"""


class PostgresEvidenceStore(EvidenceStore):
    """Same immutable records and selections, with PostgreSQL transactions.

    Writers serialize within this database/schema, like SQLite BEGIN IMMEDIATE.
    Readers use one repeatable-read snapshot across all eligibility queries.
    No connection pool, implicit authority integration, or migration is included.
    """

    def __init__(self, dsn, schema="t6_evidence"):
        if not isinstance(schema, str) or not re.fullmatch(
            r"t6_[a-z0-9_]{1,59}", schema
        ):
            raise EvidenceError("Explicit bounded t6_ schema required")
        self.dsn = dsn
        self.schema = schema
        self._lock_key = int.from_bytes(
            hashlib.sha256(schema.encode()).digest()[:8], "big", signed=True
        )
        db = self._open(True)
        try:
            self._lock(db)
            with db.cursor() as cursor:
                cursor.execute(
                    sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(
                        sql.Identifier(schema)
                    )
                )
            self._search_path(db)
            with db.cursor() as cursor:
                cursor.execute(_SCHEMA)
                for table in ("revisions", "blobs", "events"):
                    trigger = "immutable_" + table
                    cursor.execute(
                        "SELECT 1 FROM pg_catalog.pg_trigger "
                        "WHERE tgrelid=%s::regclass AND tgname=%s",
                        (f"{schema}.{table}", trigger),
                    )
                    if not cursor.fetchone():
                        cursor.execute(
                            sql.SQL(
                                "CREATE TRIGGER {} BEFORE UPDATE OR DELETE OR TRUNCATE "
                                "ON {} FOR EACH STATEMENT EXECUTE FUNCTION "
                                "reject_evidence_mutation()"
                            ).format(sql.Identifier(trigger), sql.Identifier(table))
                        )
                    trigger = "identity_keys_" + table
                    cursor.execute(
                        "SELECT 1 FROM pg_catalog.pg_trigger "
                        "WHERE tgrelid=%s::regclass AND tgname=%s",
                        (f"{schema}.{table}", trigger),
                    )
                    if not cursor.fetchone():
                        cursor.execute(
                            sql.SQL(
                                "CREATE TRIGGER {} BEFORE INSERT ON {} "
                                "FOR EACH ROW EXECUTE FUNCTION prepare_evidence_keys()"
                            ).format(sql.Identifier(trigger), sql.Identifier(table))
                        )
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _open(self, write):
        db = psycopg2.connect(
            self.dsn,
            connect_timeout=5,
            options="-c lock_timeout=10000 -c statement_timeout=15000",
        )
        db.set_session(
            isolation_level=extensions.ISOLATION_LEVEL_READ_COMMITTED
            if write
            else extensions.ISOLATION_LEVEL_REPEATABLE_READ,
            readonly=not write,
            autocommit=False,
        )
        return db

    def _lock(self, db):
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT pg_catalog.pg_advisory_xact_lock(%s)", (self._lock_key,)
            )

    def _search_path(self, db):
        with db.cursor() as cursor:
            cursor.execute(
                sql.SQL("SET search_path TO {},pg_catalog").format(
                    sql.Identifier(self.schema)
                )
            )

    @contextmanager
    def connect(self, write=False):
        db = self._open(write)
        try:
            self._search_path(db)
            if write:
                self._lock(db)
            yield _Connection(db)
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def audit(self):
        result = super().audit()
        result["backend"] = "PostgreSQL"
        result["postgresql_parity"] = "requires_external_qualification"
        return result
