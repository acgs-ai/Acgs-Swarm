"""Declarative Evolution Log — strict monotonicity + acceleration invariants.

Enforces five invariants at write time, mirroring the SQL/Prolog specification
in the declarative-evolution-guide:

1. Strict monotonicity:  value(N) > value(N-1)          — no plateaus, no regression
2. Strict acceleration:  delta(N) > delta(N-1)           — rate of improvement must grow
3. Contiguous history:   epoch N requires epoch N-1       — no gaps
4. Uniqueness:           (epoch, metric) appears once     — no overwrites
5. Minimum evidence:     ≥2 epochs for monotonicity claim; ≥3 for acceleration claim

The table is append-only: UPDATE and DELETE are blocked by triggers.
Derived quantities (delta, accel) are computed on-the-fly via a view — never stored.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class EvolutionViolationError(ValueError):
    """Base for all write-time invariant violations."""


class EvolutionLockedError(EvolutionViolationError):
    """Raised when SQLite locking prevents an admission decision."""


class MissingPriorEpochError(EvolutionViolationError):
    """Raised when the prior epoch does not exist (contiguity violation)."""


class NonIncreasingValueError(EvolutionViolationError):
    """Raised when the new value does not strictly exceed the prior value."""


class DecelerationBlockedError(EvolutionViolationError):
    """Raised when the new delta does not strictly exceed the prior delta."""


class DuplicateRecordError(EvolutionViolationError):
    """Raised when the (epoch, metric) pair already exists."""


class MutationBlockedError(EvolutionViolationError):
    """Raised when an UPDATE or DELETE is attempted on the append-only table."""


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RegressionRecord:
    metric: str
    epoch: int
    delta: float


@dataclass(frozen=True, slots=True)
class DecelerationRecord:
    metric: str
    epoch: int
    accel: float


@dataclass(frozen=True, slots=True)
class GapRecord:
    metric: str
    epoch: int  # the epoch that has no predecessor


@dataclass(frozen=True, slots=True)
class DashboardRow:
    metric: str
    baseline: float
    current_best: float
    epoch_count: int
    total_gain: float
    avg_rate: float | None
    strictly_increasing: str  # 'YES' | 'NO' | 'INSUFFICIENT DATA'
    strictly_accelerating: str  # 'YES' | 'NO' | 'INSUFFICIENT DATA'


# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_DDL_TABLE = """
CREATE TABLE IF NOT EXISTS evolution_log (
    epoch       INTEGER NOT NULL CHECK (epoch >= 1),
    metric      TEXT    NOT NULL,
    value       REAL    NOT NULL,
    recorded_at TEXT    DEFAULT (datetime('now')),
    PRIMARY KEY (epoch, metric)
) STRICT;
"""

_DDL_SCHEMA_METADATA = """
CREATE TABLE evolution_log_schema (
    singleton      INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    schema_digest  TEXT NOT NULL
) STRICT;
"""

_DDL_VIEW = """
CREATE VIEW evolution_derived AS
WITH deltas AS (
    SELECT epoch,
           metric,
           value,
           value - LAG(value) OVER (
               PARTITION BY metric
               ORDER BY epoch
           ) AS delta
    FROM evolution_log
)
SELECT epoch,
       metric,
       value,
       delta,
       delta - LAG(delta) OVER (
           PARTITION BY metric
           ORDER BY epoch
       ) AS accel
FROM deltas;
"""

_ADMISSION_RULES = (
    (
        "DUPLICATE RECORD",
        """EXISTS (
        SELECT 1
        FROM evolution_log
        WHERE epoch = {candidate}.epoch
          AND metric = {candidate}.metric
    )""",
    ),
    (
        "INVALID EPOCH",
        """typeof({candidate}.epoch) != 'integer'
       OR {candidate}.epoch < 1""",
    ),
    (
        "NON-FINITE VALUE",
        """{candidate}.value IS NULL
       OR typeof({candidate}.value) NOT IN ('integer', 'real')
       OR {candidate}.value > 1.7976931348623157e308
       OR {candidate}.value < -1.7976931348623157e308""",
    ),
    (
        "MISSING PRIOR EPOCH",
        """{candidate}.epoch > 1
      AND NOT EXISTS (
          SELECT 1
          FROM evolution_log
          WHERE metric = {candidate}.metric
            AND epoch  = {candidate}.epoch - 1
      )""",
    ),
    (
        "NON-INCREASING VALUE",
        """EXISTS (
        SELECT 1
        FROM evolution_log
        WHERE metric = {candidate}.metric
          AND epoch  = {candidate}.epoch - 1
          AND {candidate}.value <= value
    )""",
    ),
    (
        "DECELERATION BLOCKED",
        """EXISTS (
        SELECT 1
        FROM evolution_log AS cur
        JOIN evolution_log AS prev
          ON prev.metric = cur.metric
         AND prev.epoch  = cur.epoch - 1
        WHERE cur.metric = {candidate}.metric
          AND cur.epoch  = {candidate}.epoch - 1
          AND ({candidate}.value - cur.value) <= (cur.value - prev.value)
    )""",
    ),
)


def _trigger_rule_statements() -> str:
    return "\n\n".join(
        f"    SELECT RAISE(ABORT, '{code}')\n"
        f"    WHERE {condition.format(candidate='NEW')};"
        for code, condition in _ADMISSION_RULES
    )


def _admission_case() -> str:
    branches = "\n".join(
        f"    WHEN {condition.format(candidate='candidate')} THEN '{code}'"
        for code, condition in _ADMISSION_RULES
    )
    return f"CASE\n{branches}\n    ELSE NULL\nEND"


_DDL_TRIGGER_INSERT = f"""
CREATE TRIGGER validate_evolution_insert
BEFORE INSERT ON evolution_log
FOR EACH ROW
BEGIN
{_trigger_rule_statements()}
END;
"""

_Q_ADMISSION_VIOLATION = f"""
WITH candidate(epoch, metric, value) AS (VALUES (?, ?, ?))
SELECT {_admission_case()} AS violation
FROM candidate;
"""

_DDL_TRIGGER_UPDATE = """
CREATE TRIGGER block_evolution_update
BEFORE UPDATE ON evolution_log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'UPDATES BLOCKED: table is append-only');
END;
"""

_DDL_TRIGGER_DELETE = """
CREATE TRIGGER block_evolution_delete
BEFORE DELETE ON evolution_log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'DELETES BLOCKED: table is append-only');
END;
"""

_SCHEMA_VERSION = 1
_SCHEMA_OBJECTS = {
    ("table", "evolution_log_schema"): _DDL_SCHEMA_METADATA,
    ("view", "evolution_derived"): _DDL_VIEW,
    ("trigger", "validate_evolution_insert"): _DDL_TRIGGER_INSERT,
    ("trigger", "block_evolution_update"): _DDL_TRIGGER_UPDATE,
    ("trigger", "block_evolution_delete"): _DDL_TRIGGER_DELETE,
}
_MAX_FINITE = float.fromhex("0x1.fffffffffffffp+1023")
_FLOAT_SIGN_BIT = 1 << 63
_FLOAT_BITS_MASK = (1 << 64) - 1


def _normalize_sql(sql: str) -> str:
    return sql.strip().removesuffix(";").rstrip()


def _schema_digest(objects: dict[tuple[str, str], str]) -> str:
    payload = [
        {"name": name, "sql": _normalize_sql(sql), "type": object_type}
        for (object_type, name), sql in sorted(objects.items())
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


_EXPECTED_TABLE_SQL = _normalize_sql(_DDL_TABLE).replace(
    "CREATE TABLE IF NOT EXISTS", "CREATE TABLE", 1
)
_EXPECTED_SCHEMA_DIGEST = _schema_digest(_SCHEMA_OBJECTS)


def _float_to_ordered_int(value: float) -> int:
    bits = struct.unpack(">Q", struct.pack(">d", value))[0]
    if bits & _FLOAT_SIGN_BIT:
        return (~bits) & _FLOAT_BITS_MASK
    return bits | _FLOAT_SIGN_BIT


def _ordered_int_to_float(value: int) -> float:
    if value & _FLOAT_SIGN_BIT:
        bits = value & ~_FLOAT_SIGN_BIT
    else:
        bits = (~value) & _FLOAT_BITS_MASK
    return struct.unpack(">d", struct.pack(">Q", bits))[0]

# ---------------------------------------------------------------------------
# Invariant queries
# ---------------------------------------------------------------------------

_Q_REGRESSION = """
SELECT metric, epoch AS regressed_at, delta
FROM evolution_derived
WHERE delta IS NOT NULL AND delta <= 0;
"""

_Q_DECELERATION = """
SELECT metric, epoch AS decel_at, accel
FROM evolution_derived
WHERE accel IS NOT NULL AND accel <= 0;
"""

_Q_GAPS = """
SELECT cur.metric, cur.epoch AS has_no_predecessor
FROM evolution_log AS cur
LEFT JOIN evolution_log AS prev
  ON prev.metric = cur.metric
 AND prev.epoch  = cur.epoch - 1
WHERE cur.epoch > 1
  AND prev.epoch IS NULL;
"""

_Q_DASHBOARD = """
SELECT metric,
       MIN(value)  AS baseline,
       MAX(value)  AS current_best,
       COUNT(*)    AS epoch_count,
       ROUND(MAX(value) - MIN(value), 2) AS total_gain,
       ROUND(AVG(delta), 2)              AS avg_rate,
       CASE
           WHEN COUNT(CASE WHEN delta IS NOT NULL THEN 1 END) < 1
               THEN 'INSUFFICIENT DATA'
           WHEN MIN(CASE WHEN delta IS NOT NULL THEN delta END) > 0
               THEN 'YES'
           ELSE 'NO'
       END AS strictly_increasing,
       CASE
           WHEN COUNT(CASE WHEN accel IS NOT NULL THEN 1 END) < 1
               THEN 'INSUFFICIENT DATA'
           WHEN MIN(CASE WHEN accel IS NOT NULL THEN accel END) > 0
               THEN 'YES'
           ELSE 'NO'
       END AS strictly_accelerating
FROM evolution_derived
GROUP BY metric;
"""


# ---------------------------------------------------------------------------
# EvolutionLog
# ---------------------------------------------------------------------------


class EvolutionLog:
    """SQLite-backed append-only log enforcing the declarative evolution contract.

    Usage::

        with EvolutionLog(":memory:") as log:
            log.record(1, "capability", 10.0)
            log.record(2, "capability", 12.0)
            assert log.dashboard()[0].strictly_increasing == "YES"

    Parameters
    ----------
    path:
        File path for the SQLite database, or ``":memory:"`` for an in-memory DB.
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        self._conn: sqlite3.Connection | None = None
        self._read_only = False

    # ------------------------------------------------------------------
    # Context manager / lifecycle
    # ------------------------------------------------------------------

    def open(self, *, read_only: bool = False) -> EvolutionLog:
        """Open the log, optionally in verify-only SQLite read-only mode."""
        if self._conn is not None:
            if read_only != self._read_only:
                raise EvolutionViolationError(
                    "evolution log is already open in a different access mode"
                )
            return self
        if read_only:
            if self._path == ":memory:":
                raise EvolutionViolationError(
                    "read-only mode requires a file-backed evolution log"
                )
            database_uri = Path(self._path).resolve().as_uri() + "?mode=ro"
            conn = sqlite3.connect(database_uri, uri=True)
        else:
            conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        self._conn = conn
        self._read_only = read_only
        try:
            if read_only:
                conn.execute("PRAGMA query_only = ON")
                self._verify_canonical_schema(validate_history=True)
            else:
                self._setup()
        except Exception:
            conn.close()
            self._conn = None
            self._read_only = False
            raise
        return self

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
            self._read_only = False

    def __enter__(self) -> EvolutionLog:
        if self._conn is not None:
            return self
        return self.open()

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _setup(self) -> None:
        assert self._conn is not None
        with self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(_DDL_TABLE)
            self._validate_primary_table_schema()
            self._validate_history()
            version, stored_digest = self._schema_state()
            if version > _SCHEMA_VERSION:
                raise EvolutionViolationError(
                    f"unsupported evolution schema version {version}"
                )

            actual_digest = self._actual_schema_digest()
            if (
                version != _SCHEMA_VERSION
                or stored_digest != _EXPECTED_SCHEMA_DIGEST
                or actual_digest != _EXPECTED_SCHEMA_DIGEST
            ):
                self._recreate_owned_schema()

            self._verify_canonical_schema(validate_history=False)

    def _validate_primary_table_schema(self) -> None:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
            ("evolution_log",),
        ).fetchone()
        if (
            row is None
            or not isinstance(row["sql"], str)
            or _normalize_sql(row["sql"]) != _EXPECTED_TABLE_SQL
        ):
            raise EvolutionViolationError(
                "evolution_log table does not match the canonical definition"
            )

    def _schema_state(self) -> tuple[int, str | None]:
        assert self._conn is not None
        exists = self._conn.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?",
            ("evolution_log_schema",),
        ).fetchone()
        if exists is None:
            return 0, None
        try:
            rows = self._conn.execute(
                "SELECT singleton, schema_version, schema_digest "
                "FROM evolution_log_schema"
            ).fetchall()
        except sqlite3.Error as exc:
            raise EvolutionViolationError(
                "evolution schema metadata is unreadable"
            ) from exc
        if len(rows) != 1 or rows[0]["singleton"] != 1:
            return 0, None
        version = rows[0]["schema_version"]
        digest = rows[0]["schema_digest"]
        if not isinstance(version, int) or not isinstance(digest, str):
            raise EvolutionViolationError("evolution schema metadata is invalid")
        return version, digest

    def _actual_schema_digest(self) -> str | None:
        assert self._conn is not None
        actual: dict[tuple[str, str], str] = {}
        for object_type, name in _SCHEMA_OBJECTS:
            row = self._conn.execute(
                "SELECT sql FROM sqlite_schema WHERE type = ? AND name = ?",
                (object_type, name),
            ).fetchone()
            if row is None or not isinstance(row["sql"], str):
                return None
            actual[(object_type, name)] = row["sql"]
        return _schema_digest(actual)

    def _unexpected_triggers(self) -> list[str]:
        assert self._conn is not None
        expected = {
            name
            for object_type, name in _SCHEMA_OBJECTS
            if object_type == "trigger"
        }
        rows = self._conn.execute(
            "SELECT name, 'main' AS schema_name FROM sqlite_schema "
            "WHERE type = 'trigger' AND tbl_name = 'evolution_log' "
            "UNION ALL "
            "SELECT name, 'temp' AS schema_name FROM sqlite_temp_schema "
            "WHERE type = 'trigger' AND tbl_name = 'evolution_log'"
        ).fetchall()
        return sorted(
            (
                row["name"]
                if row["schema_name"] == "main"
                else f"temp.{row['name']}"
            )
            for row in rows
            if row["schema_name"] == "temp" or row["name"] not in expected
        )

    def _verify_canonical_schema(self, *, validate_history: bool) -> None:
        self._validate_primary_table_schema()
        version, stored_digest = self._schema_state()
        if version != _SCHEMA_VERSION:
            raise EvolutionViolationError(
                f"evolution schema version {version} is not canonical"
            )
        if stored_digest != _EXPECTED_SCHEMA_DIGEST:
            raise EvolutionViolationError(
                "stored evolution schema digest is not canonical"
            )
        if self._actual_schema_digest() != _EXPECTED_SCHEMA_DIGEST:
            raise EvolutionViolationError(
                "evolution schema does not match the canonical definition"
            )
        unexpected = self._unexpected_triggers()
        if unexpected:
            names = ", ".join(unexpected)
            raise EvolutionViolationError(
                f"evolution schema contains unexpected trigger(s): {names}"
            )
        if validate_history:
            self._validate_history()

    def _recreate_owned_schema(self) -> None:
        assert self._conn is not None
        for object_type, name in reversed(_SCHEMA_OBJECTS):
            self._conn.execute(f'DROP {object_type.upper()} IF EXISTS "{name}"')
        for ddl in _SCHEMA_OBJECTS.values():
            self._conn.execute(ddl)
        self._conn.execute(
            "INSERT INTO evolution_log_schema "
            "(singleton, schema_version, schema_digest) VALUES (1, ?, ?)",
            (_SCHEMA_VERSION, _EXPECTED_SCHEMA_DIGEST),
        )

    def _validate_history(self) -> None:
        assert self._conn is not None
        try:
            rows = self._conn.execute(
                "SELECT epoch, metric, value FROM evolution_log "
                "ORDER BY metric, epoch"
            ).fetchall()
        except sqlite3.Error as exc:
            raise EvolutionViolationError(
                "evolution history schema is incompatible"
            ) from exc

        histories: dict[str, list[tuple[int, float]]] = {}
        seen: set[tuple[int, str]] = set()
        for row in rows:
            epoch = row["epoch"]
            metric = row["metric"]
            value = row["value"]
            if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
                raise EvolutionViolationError("evolution history contains an invalid epoch")
            if not isinstance(metric, str):
                raise EvolutionViolationError("evolution history contains an invalid metric")
            if not isinstance(value, (int, float)) or not math.isfinite(value):
                raise EvolutionViolationError(
                    "evolution history contains a non-finite value"
                )
            key = (epoch, metric)
            if key in seen:
                raise EvolutionViolationError(
                    "evolution history contains a duplicate record"
                )
            seen.add(key)
            histories.setdefault(metric, []).append((epoch, float(value)))

        for metric, points in histories.items():
            for index, (epoch, value) in enumerate(points):
                expected_epoch = index + 1
                if epoch != expected_epoch:
                    raise EvolutionViolationError(
                        f"evolution history for metric '{metric}' has a gap at epoch {epoch}"
                    )
                if index >= 1 and value <= points[index - 1][1]:
                    raise EvolutionViolationError(
                        f"evolution history for metric '{metric}' is not increasing"
                    )
                if index >= 2:
                    delta = value - points[index - 1][1]
                    prior_delta = points[index - 1][1] - points[index - 2][1]
                    if delta <= prior_delta:
                        raise EvolutionViolationError(
                            f"evolution history for metric '{metric}' is not accelerating"
                        )

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    @staticmethod
    def _finite_value(value: object) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise EvolutionViolationError("evolution values must be finite numbers")
        try:
            normalized = float(value)
        except OverflowError as exc:
            raise EvolutionViolationError(
                "evolution values must be finite numbers"
            ) from exc
        if not math.isfinite(normalized):
            raise EvolutionViolationError("evolution values must be finite numbers")
        return normalized

    @classmethod
    def _validated_input(cls, epoch: object, metric: object, value: object) -> float:
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
            raise EvolutionViolationError("epoch must be a positive integer")
        if not isinstance(metric, str):
            raise EvolutionViolationError("metric must be a string")
        return cls._finite_value(value)

    @staticmethod
    def _write_violation(
        exc: sqlite3.Error, epoch: int, metric: str, value: float
    ) -> EvolutionViolationError | None:
        msg = str(exc)
        if "MISSING PRIOR EPOCH" in msg:
            return MissingPriorEpochError(
                f"epoch {epoch} for metric '{metric}' requires epoch {epoch - 1}"
            )
        if "NON-INCREASING VALUE" in msg:
            return NonIncreasingValueError(
                f"value {value} for metric '{metric}' epoch {epoch} "
                "does not strictly exceed the prior value"
            )
        if "DECELERATION BLOCKED" in msg:
            return DecelerationBlockedError(
                f"delta for metric '{metric}' epoch {epoch} "
                "does not strictly exceed the prior delta"
            )
        if "UPDATES BLOCKED" in msg or "DELETES BLOCKED" in msg:
            return MutationBlockedError(msg)
        if "DUPLICATE RECORD" in msg or "UNIQUE constraint failed" in msg:
            return DuplicateRecordError(
                f"(epoch={epoch}, metric='{metric}') already exists in evolution_log"
            )
        if "NON-FINITE VALUE" in msg:
            return EvolutionViolationError("evolution values must be finite numbers")
        return None

    def record(self, epoch: int, metric: str, value: float) -> None:
        """Insert a new (epoch, metric, value) data point.

        Raises
        ------
        MissingPriorEpochError
            If epoch > 1 and the prior epoch does not exist.
        NonIncreasingValueError
            If the new value does not strictly exceed the prior value.
        DecelerationBlockedError
            If the new delta does not strictly exceed the prior delta.
        DuplicateRecordError
            If the (epoch, metric) pair already exists.
        """
        normalized = self._validated_input(epoch, metric, value)
        assert self._conn is not None
        if self._read_only:
            raise EvolutionViolationError("evolution log is opened read-only")
        try:
            with self._conn:
                self._conn.execute("BEGIN IMMEDIATE")
                self._verify_canonical_schema(validate_history=False)
                self._conn.execute(
                    "INSERT INTO evolution_log (epoch, metric, value) VALUES (?, ?, ?)",
                    (epoch, metric, normalized),
                )
        except sqlite3.Error as exc:
            violation = self._write_violation(exc, epoch, metric, normalized)
            if violation is not None:
                raise violation from exc
            raise

    # ------------------------------------------------------------------
    # Invariant queries
    # ------------------------------------------------------------------

    def detect_regression(self) -> list[RegressionRecord]:
        """Return rows where value failed to strictly increase."""
        assert self._conn is not None
        rows = self._conn.execute(_Q_REGRESSION).fetchall()
        return [
            RegressionRecord(metric=r["metric"], epoch=r["regressed_at"], delta=r["delta"])
            for r in rows
        ]

    def detect_deceleration(self) -> list[DecelerationRecord]:
        """Return rows where the rate of improvement failed to strictly increase."""
        assert self._conn is not None
        rows = self._conn.execute(_Q_DECELERATION).fetchall()
        return [
            DecelerationRecord(metric=r["metric"], epoch=r["decel_at"], accel=r["accel"])
            for r in rows
        ]

    def detect_gaps(self) -> list[GapRecord]:
        """Return epochs that exist but whose predecessor does not."""
        assert self._conn is not None
        rows = self._conn.execute(_Q_GAPS).fetchall()
        return [GapRecord(metric=r["metric"], epoch=r["has_no_predecessor"]) for r in rows]

    def dashboard(self) -> list[DashboardRow]:
        """Return per-metric summary with strictly_increasing / strictly_accelerating flags."""
        assert self._conn is not None
        rows = self._conn.execute(_Q_DASHBOARD).fetchall()
        return [
            DashboardRow(
                metric=r["metric"],
                baseline=r["baseline"],
                current_best=r["current_best"],
                epoch_count=r["epoch_count"],
                total_gain=r["total_gain"],
                avg_rate=r["avg_rate"],
                strictly_increasing=r["strictly_increasing"],
                strictly_accelerating=r["strictly_accelerating"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Admission gate (dry-run against the write-time invariant)
    # ------------------------------------------------------------------

    def admit(self, metric: str, epoch: int, value: float) -> bool:
        """Return True iff inserting (epoch, metric, value) would satisfy all invariants.

        This gate evaluates the same SQL rule definitions used to build the
        insert trigger, without opening a write transaction.
        """
        try:
            normalized = self._validated_input(epoch, metric, value)
        except EvolutionViolationError:
            return False
        assert self._conn is not None
        try:
            self._verify_canonical_schema(validate_history=False)
            return self._admission_violation(metric, epoch, normalized) is None
        except sqlite3.OperationalError as exc:
            error_code = getattr(exc, "sqlite_errorcode", None)
            if isinstance(error_code, int) and error_code & 0xFF in {
                sqlite3.SQLITE_BUSY,
                sqlite3.SQLITE_LOCKED,
            }:
                raise EvolutionLockedError(
                    "evolution log is locked; admission could not be evaluated"
                ) from exc
            raise

    def _admission_violation(
        self, metric: str, epoch: int, value: float
    ) -> str | None:
        assert self._conn is not None
        row = self._conn.execute(
            _Q_ADMISSION_VIOLATION,
            (epoch, metric, value),
        ).fetchone()
        if row is None:
            raise EvolutionViolationError("evolution admission predicate returned no result")
        violation = row["violation"]
        if violation is not None and not isinstance(violation, str):
            raise EvolutionViolationError(
                "evolution admission predicate returned an invalid result"
            )
        return violation

    # ------------------------------------------------------------------
    # Minimum admissible value (mirrors admissible_min/3 from guide §2.7)
    # ------------------------------------------------------------------

    def admissible_min(self, metric: str, epoch: int) -> float:
        """Return the least finite binary64 value admissible at ``epoch``.

        Raises
        ------
        EvolutionViolationError
            If history is missing, the target is occupied, or no finite value
            can satisfy the write-time invariant.
        """
        assert self._conn is not None
        self._verify_canonical_schema(validate_history=False)
        cur = self._conn.cursor()

        if epoch < 2:
            raise EvolutionViolationError("admissible_min requires epoch >= 2")

        occupied = cur.execute(
            "SELECT 1 FROM evolution_log WHERE epoch = ? AND metric = ?",
            (epoch, metric),
        ).fetchone()
        if occupied is not None:
            raise EvolutionViolationError(
                f"epoch {epoch} for metric '{metric}' already exists"
            )

        prior = cur.execute(
            "SELECT value FROM evolution_log WHERE epoch = ? AND metric = ?",
            (epoch - 1, metric),
        ).fetchone()
        if prior is None:
            raise EvolutionViolationError(
                f"epoch {epoch - 1} for metric '{metric}' not found"
            )

        prior_value = float(prior[0])
        lower = math.nextafter(prior_value, math.inf)
        if not math.isfinite(lower) or self._admission_violation(
            metric, epoch, _MAX_FINITE
        ) is not None:
            raise EvolutionViolationError(
                f"no finite value is admissible for metric '{metric}' epoch {epoch}"
            )

        low_key = _float_to_ordered_int(lower)
        high_key = _float_to_ordered_int(_MAX_FINITE)
        while low_key < high_key:
            middle_key = (low_key + high_key) // 2
            candidate = _ordered_int_to_float(middle_key)
            if self._admission_violation(metric, epoch, candidate) is None:
                high_key = middle_key
            else:
                low_key = middle_key + 1

        candidate = _ordered_int_to_float(low_key)
        predecessor = math.nextafter(candidate, -math.inf)
        if (
            self._admission_violation(metric, epoch, candidate) is not None
            or self._admission_violation(metric, epoch, predecessor) is None
        ):
            raise EvolutionViolationError(
                "could not prove the minimum admissible finite value"
            )
        return candidate

    # ------------------------------------------------------------------
    # Full-path validation (mirrors valid_trajectory/3 from guide §2.8)
    # ------------------------------------------------------------------

    def valid_trajectory(self, metric: str, from_epoch: int, to_epoch: int) -> bool:
        """Return True iff every step in [from_epoch..to_epoch] satisfies the contract.

        Checks contiguity, strict increase at every consecutive pair, and strict
        acceleration at every triple (where defined). A single-epoch range is
        trivially valid if that epoch exists.
        """
        assert self._conn is not None
        cur = self._conn.cursor()

        if from_epoch > to_epoch:
            return False

        # Check all epochs exist contiguously
        rows = cur.execute(
            "SELECT epoch, value FROM evolution_log "
            "WHERE metric = ? AND epoch BETWEEN ? AND ? "
            "ORDER BY epoch",
            (metric, from_epoch, to_epoch),
        ).fetchall()

        epochs_found = [r[0] for r in rows]
        expected = list(range(from_epoch, to_epoch + 1))
        if epochs_found != expected:
            return False  # gap or missing epochs

        values = [r[1] for r in rows]

        # Strict increase at every consecutive pair
        for i in range(1, len(values)):
            delta = values[i] - values[i - 1]
            if delta <= 0:
                return False

        # Strict acceleration at every triple
        for i in range(2, len(values)):
            d_cur = values[i] - values[i - 1]
            d_prev = values[i - 1] - values[i - 2]
            if d_cur <= d_prev:
                return False

        return True
