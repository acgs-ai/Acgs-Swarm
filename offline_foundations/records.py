"""Strict immutable JSON records and SQLite transactions; standard library only."""

import hashlib
import json
import math
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


class ContractError(ValueError):
    pass


def canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 512:
        raise ContractError("Identity must be a nonempty bounded string")
    return value


def hash_id(value):
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ContractError("A complete lowercase SHA-256 identity is required")
    return value


def number(value, low=0, high=1):
    if (
        type(value) not in (int, float)
        or not low <= value <= high
        or not math.isfinite(value)
    ):
        raise ContractError(
            "Expected a finite real number in the declared range; booleans are invalid"
        )
    return float(value)


def integer(value, low=0):
    if type(value) is not int or value < low:
        raise ContractError("Expected a nonnegative integer, not a boolean")
    return value


@dataclass(frozen=True)
class FrozenRecord:
    serialized: str

    @classmethod
    def seal(cls, value):
        return cls(canonical(value))

    @property
    def data(self):
        return json.loads(self.serialized)

    @property
    def digest(self):
        return sha(self.serialized.encode("utf-8"))


class Database:
    def __init__(self, path, schema):
        self.path = Path(path).absolute()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.executescript(schema)

    @contextmanager
    def connect(self, write=False):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()


def append_only(table):
    return (
        f"CREATE TRIGGER IF NOT EXISTS immutable_{table}_update BEFORE UPDATE ON {table} "
        "BEGIN SELECT RAISE(ABORT,'append-only'); END;"
        f"CREATE TRIGGER IF NOT EXISTS immutable_{table}_delete BEFORE DELETE ON {table} "
        "BEGIN SELECT RAISE(ABORT,'append-only'); END;"
    )
