"""Optional-extra collection hooks.

The frozen PostgreSQL suite (`tests/test_apcc_postgres.py`) must not be
collected without psycopg. Several of its tests import the postgres backend at
call time and would fail the default ``[dev]`` matrix. Live-store tests still
skip without ``APCC_POSTGRES_DSN`` when psycopg is present.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

collect_ignore: list[str] = []

try:
    import psycopg  # noqa: F401
except ImportError:
    collect_ignore.append("test_apcc_postgres.py")


@pytest.fixture
def assert_swarm_normalization_catches() -> Callable[[str, dict], None]:
    """Check that Swarm's own normalization defeats a Unicode/separator evasion.

    acgs-lite >= 4.0.0 folds NFKC and drops default-ignorable code points inside the
    engine, so for some payloads the raw pass already catches the evasion and
    ``normalization_added_catch`` is legitimately False. An engine-based check alone
    would then pass even if Swarm's normalization regressed, so the first assertion
    inspects ``normalize_payload`` output directly, without the engine.

    Only for evasions whose canonical form is ASCII (fullwidth, invisible separators,
    combining marks, Cyrillic/Greek homoglyphs). ``isascii()`` is a coarse proxy; the
    engine check on the folded text confirms the keyword was actually rejoined.
    """
    from constitutional_swarm.eval.monotonic_mas.detectors import role

    def check(payload: str, details: dict) -> None:
        normalized = role.normalize_payload(payload)
        # Engine-independent: Swarm itself folds every evasion to plain ASCII.
        assert normalized.isascii(), (normalized, details)
        # The folded text alone must trip the lexical channels (mirrors evaluate_payload's
        # lexical_caught at the default threshold).
        agent = role._get_agent()
        n_norm, risk_norm, _, _ = role._validate_one(agent, normalized)
        assert n_norm > 0 or risk_norm >= role.RISK_THRESHOLD, (normalized, details)
        # Where the engine misses the raw payload, the catch must be credited to normalization.
        n_raw, risk_raw, _, _ = role._validate_one(agent, payload)
        if not (n_raw > 0 or risk_raw >= role.RISK_THRESHOLD):
            assert details["normalization_added_catch"] is True, details

    return check
