import sqlite3

import pytest

from offline_foundations.prompt_ledger import (
    LedgerError,
    PromptLedger,
    dataset_manifest,
    full_manifest,
)


def data():
    return [
        {
            "family_id": f"family-{i}",
            "source_family": f"source-{i}",
            "pattern": f"pattern-{i}",
            "split": "train" if i < 20 else "selection" if i < 30 else "test",
            "tasks": [
                {
                    "task_id": f"task-{i}-{j}",
                    "paraphrase": f"Synthetic maintenance fixture {i}, variant {j}",
                    "expected": "recorded-correct-or-declared-denial",
                }
                for j in range(2)
            ],
        }
        for i in range(60)
    ]


def config():
    return {
        "task_instruction": "Review this synthetic change.",
        "system_instruction": "Read-only fixture harness.",
        "policy_digest": "a" * 64,
        "tool_schema_digest": "b" * 64,
        "evaluator_digest": "c" * 64,
    }


def manifest(candidate, arm="P1", seed=0):
    return full_manifest(
        candidate=candidate,
        model="1" * 64,
        decoding="2" * 64,
        dataset=dataset_manifest(data()).digest,
        source_snapshot="4" * 64,
        memory_snapshot="5" * 64,
        evaluator="c" * 64,
        policy="a" * 64,
        tool_schema="b" * 64,
        namespace={"experiment": "exp", "arm": arm, "seed": seed},
    )


@pytest.fixture
def ledger(tmp_path):
    obj = PromptLedger(tmp_path / "prompt.db")
    obj.create_experiment(
        "exp",
        dataset_manifest(data()),
        config(),
        {
            "model": "1" * 64,
            "decoding": "2" * 64,
            "source_snapshot": "4" * 64,
            "memory_snapshot": "5" * 64,
        },
    )
    return obj


def register(ledger, arm="P1", seed=0, prompt="Specify the expected behavior."):
    return ledger.register_candidate(
        "exp", arm, seed, {"task_instruction": prompt}
    ).data


def complete_selection(ledger, candidate, arm="P1", seed=0, score=1):
    for i in range(20, 30):
        for j in range(2):
            attempt = ledger.reserve(
                "exp",
                arm,
                seed,
                candidate["candidate_digest"],
                f"task-{i}-{j}",
                "selection",
                manifest(candidate["candidate_digest"], arm, seed),
            )
            ledger.finish(
                attempt,
                score=score,
                status="success",
                raw_output="recorded fixture outcome",
                failure_type=None,
            )


def freeze(ledger):
    baseline = register(ledger, "P0", 0, config()["task_instruction"])
    a = register(ledger, "P1", 0)
    b = register(ledger, "P2", 0, "Use exact evidence references.")
    complete_selection(ledger, a)
    complete_selection(ledger, b, "P2")
    return ledger.freeze_selection("exp"), baseline, a, b


def test_family_split_isolation_and_proposer_visibility(ledger):
    visible = ledger.dataset_view("exp", "proposer").data
    assert len(visible["families"]) == 20
    assert all(f["split"] == "train" for f in visible["families"])
    with pytest.raises(LedgerError):
        ledger.dataset_view("exp", "proposer", split="test")
    bad = data()
    bad[30]["source_family"] = bad[0]["source_family"]
    with pytest.raises(LedgerError):
        dataset_manifest(bad)
    bad = data()
    bad[30]["pattern"] = bad[0]["pattern"]
    with pytest.raises(LedgerError):
        dataset_manifest(bad)


def test_only_one_prompt_slot_and_immutable_candidates(ledger):
    a = register(ledger)
    assert (
        ledger.candidate(a["candidate_digest"]).data["configuration"][
            "system_instruction"
        ]
        == config()["system_instruction"]
    )
    with pytest.raises(LedgerError):
        ledger.register_candidate("exp", "P1", 0, {"policy_digest": "f" * 64})
    with pytest.raises(LedgerError):
        ledger.register_candidate("exp", "P1", 0, {"task_instruction": "x" * 4097})
    with sqlite3.connect(ledger.path) as db, pytest.raises(sqlite3.IntegrityError):
        db.execute("UPDATE candidates SET body='{}'")
    for n in range(2):
        register(ledger, prompt=f"Candidate slot {n}")
    with pytest.raises(LedgerError):
        register(ledger, prompt="Fifth slot")


def test_full_manifest_changes_cache_namespace(ledger):
    candidate = register(ledger)
    base = manifest(candidate["candidate_digest"])
    key = ledger.cache_key(base, "train", "task-0-0")
    for field in (
        "model",
        "decoding",
        "dataset",
        "source_snapshot",
        "memory_snapshot",
        "evaluator",
        "policy",
        "tool_schema",
    ):
        changed = base.data
        changed[field] = "f" * 64
        assert ledger.cache_key(changed, "train", "task-0-0") != key
    assert ledger.cache_key(base, "test", "task-0-0") != key
    attempt = ledger.reserve(
        "exp", "P1", 0, candidate["candidate_digest"], "task-0-0", "train", base
    )
    ledger.finish(
        attempt, score=1, status="success", raw_output="original", failure_type=None
    )
    ledger.cache_put(attempt)
    assert (
        ledger.cache_get(base, "train", "task-0-0", "proposer").data["raw_output"]
        == "original"
    )
    assert ledger.counts("exp")["task_executions"] == 1
    assert ledger.counts("exp")["cache_hits"] == 1
    with pytest.raises(LedgerError):
        ledger.cache_get(base, "test", "task-0-0", "proposer")


def test_failure_retry_reservation_and_restart_accounting(ledger):
    candidate = register(ledger)
    m = manifest(candidate["candidate_digest"])
    first = ledger.reserve(
        "exp", "P1", 0, candidate["candidate_digest"], "task-0-0", "train", m
    )
    ledger.finish(
        first, score=0, status="timeout", raw_output="", failure_type="infrastructure"
    )
    retry = ledger.reserve(
        "exp",
        "P1",
        0,
        candidate["candidate_digest"],
        "task-0-0",
        "train",
        m,
        retry_of=first,
    )
    ledger.finish(
        retry, score=1, status="success", raw_output="recorded retry", failure_type=None
    )
    ledger.reserve(
        "exp", "P1", 0, candidate["candidate_digest"], "task-1-0", "reflection", m
    )
    assert PromptLedger(ledger.path).counts("exp")["task_executions"] == 3
    assert ledger.counts("exp")["incomplete_reservations"] == 1
    assert (
        ledger.feedback("exp", "proposer", arm="P1", seed=0).data["records"][0][
            "status"
        ]
        == "timeout"
    )


def test_exact_search_budget_includes_failure_and_retry(ledger):
    candidate = register(ledger)
    m = manifest(candidate["candidate_digest"])
    for i in range(240):
        attempt = ledger.reserve(
            "exp", "P1", 0, candidate["candidate_digest"], "task-0-0", "reflection", m
        )
        ledger.finish(
            attempt,
            score=0,
            status="malformed",
            raw_output="raw-invalid",
            failure_type="schema",
        )
    with pytest.raises(LedgerError):
        ledger.reserve(
            "exp", "P1", 0, candidate["candidate_digest"], "task-0-0", "train", m
        )
    assert ledger.counts("exp")["task_executions"] == 240


def test_incomplete_selection_cannot_win_or_open_holdout(ledger):
    register(ledger, "P0", 0, config()["task_instruction"])
    partial = register(ledger)
    with pytest.raises(LedgerError):
        ledger.freeze_selection("exp")
    with pytest.raises(LedgerError):
        ledger.reserve(
            "exp",
            "P1",
            0,
            partial["candidate_digest"],
            "task-30-0",
            "test",
            manifest(partial["candidate_digest"]),
        )
    assert ledger.counts("exp")["task_executions"] == 0


def test_selection_freeze_precedes_holdout_and_is_immutable(ledger):
    chosen, _baseline, a, b = freeze(ledger)
    assert (
        chosen.data["P1"] == a["candidate_digest"]
        and chosen.data["P2"] == b["candidate_digest"]
    )
    assert ledger.freeze_selection("exp").digest == chosen.digest
    with pytest.raises(LedgerError):
        register(ledger, prompt="Tune after selection")
    with pytest.raises(LedgerError):
        ledger.reserve(
            "exp",
            "P1",
            0,
            a["candidate_digest"],
            "task-20-0",
            "selection",
            manifest(a["candidate_digest"]),
        )
    attempt = ledger.reserve(
        "exp",
        "P1",
        0,
        a["candidate_digest"],
        "task-30-0",
        "test",
        manifest(a["candidate_digest"]),
    )
    ledger.finish(
        attempt,
        score=0,
        status="failure",
        raw_output="recorded failure",
        failure_type="correctness",
    )
    assert ledger.promotion_status("exp") == "not_evaluated"
    assert ledger.feedback("exp", "proposer", arm="P1", seed=0).data["records"] == []


def test_complete_selection_tie_break_and_severe_violation_quarantine(ledger):
    register(ledger, "P0", 0, config()["task_instruction"])
    long = register(ledger, prompt="A longer candidate instruction.")
    short = register(ledger, "P1", 1, prompt="Short.")
    typed = register(ledger, "P2", 0)
    complete_selection(ledger, long)
    complete_selection(ledger, short, "P1", 1)
    complete_selection(ledger, typed, "P2")
    assert ledger.freeze_selection("exp").data["P1"] == short["candidate_digest"]


def test_final_budget_counts_retries_and_incomplete_matrix(ledger):
    _chosen, baseline, _a, _b = freeze(ledger)
    prior = None
    for i in range(180):
        attempt = ledger.reserve(
            "exp",
            "P0",
            0,
            baseline["candidate_digest"],
            "task-30-0",
            "test",
            manifest(baseline["candidate_digest"], "P0"),
            retry_of=prior,
        )
        ledger.finish(
            attempt,
            score=0,
            status="timeout",
            raw_output="",
            failure_type="infrastructure",
        )
        prior = attempt
    with pytest.raises(LedgerError):
        ledger.reserve(
            "exp",
            "P0",
            0,
            baseline["candidate_digest"],
            "task-30-0",
            "test",
            manifest(baseline["candidate_digest"], "P0"),
        )
    assert ledger.final_status("exp") == "incomplete_inconclusive"


def test_feedback_record_identity_and_correct_denial_score(ledger):
    candidate = register(ledger, "P2")
    attempt = ledger.reserve(
        "exp",
        "P2",
        0,
        candidate["candidate_digest"],
        "task-0-0",
        "train",
        manifest(candidate["candidate_digest"], "P2"),
    )
    ledger.finish(
        attempt,
        score=1,
        status="correct_denial",
        raw_output="declared valid denial",
        failure_type="correct_policy_denial",
    )
    record = ledger.feedback("exp", "proposer", arm="P2", seed=0).data["records"][0]
    assert (
        record["score"] == 1
        and record["candidate_digest"] == candidate["candidate_digest"]
    )
    assert record["evaluator_digest"] == "c" * 64
    assert record["model_calls_executed"] == 0


def test_seed_counts_as_slot_and_recorded_proposer_accounting(ledger):
    with sqlite3.connect(ledger.path) as db:
        assert (
            db.execute(
                "SELECT COUNT(*) FROM registrations WHERE arm='P1' AND seed=0"
            ).fetchone()[0]
            == 1
        )
    ledger.record_proposal(
        "exp", "P1", 0, "p1", raw="synthetic proposal", tokens=100, failure_type=None
    )
    ledger.record_proposal(
        "exp",
        "P1",
        0,
        "p2",
        raw="malformed recorded proposal",
        tokens=50,
        failure_type="schema",
    )
    assert ledger.counts("exp")["recorded_proposer_tokens"] == 150
    assert ledger.counts("exp")["recorded_proposal_events"] == 2
    assert ledger.counts("exp")["model_calls_executed"] == 0
    with pytest.raises(LedgerError):
        ledger.record_proposal(
            "exp", "P1", 0, "p3", raw="over allocation", tokens=16000, failure_type=None
        )


def test_severe_recorded_violation_excludes_candidate(ledger):
    bad = register(ledger, prompt="Bad candidate.")
    good = register(ledger, "P1", 1, prompt="Compliant candidate.")
    typed = register(ledger, "P2", 0, prompt="Typed candidate.")
    complete_selection(ledger, bad, score=1)
    attempt = ledger.reserve(
        "exp",
        "P1",
        0,
        bad["candidate_digest"],
        "task-0-0",
        "train",
        manifest(bad["candidate_digest"]),
    )
    ledger.finish(
        attempt,
        score=0,
        status="failure",
        raw_output="rejected raw output",
        failure_type="scope_violation",
    )
    complete_selection(ledger, good, "P1", 1, score=0.5)
    complete_selection(ledger, typed, "P2")
    assert ledger.freeze_selection("exp").data["P1"] == good["candidate_digest"]


def test_runtime_identity_cannot_change_across_selection_or_holdout(ledger):
    chosen, baseline, _a, _b = freeze(ledger)
    assert chosen.data["runtime_identity"]["model"] == "1" * 64
    for field in ("model", "decoding", "source_snapshot", "memory_snapshot"):
        altered = manifest(baseline["candidate_digest"], "P0").data
        altered[field] = "f" * 64
        with pytest.raises(LedgerError):
            ledger.reserve(
                "exp",
                "P0",
                0,
                baseline["candidate_digest"],
                "task-30-0",
                "test",
                altered,
            )


def test_pending_original_prevents_freeze_and_cannot_be_replaced(ledger):
    a = register(ledger)
    pending = ledger.reserve(
        "exp",
        "P1",
        0,
        a["candidate_digest"],
        "task-20-0",
        "selection",
        manifest(a["candidate_digest"]),
    )
    complete_selection(ledger, a)
    b = register(ledger, "P2")
    complete_selection(ledger, b, "P2")
    with pytest.raises(LedgerError):
        ledger.freeze_selection("exp")
    ledger.finish(
        pending,
        score=0,
        status="failure",
        raw_output="recorded scope violation",
        failure_type="scope_violation",
    )
    with pytest.raises(LedgerError):
        ledger.freeze_selection("exp")


def test_six_search_namespaces_and_total_caps_are_inclusive(ledger):
    # Each reservation counts even when the recorded task never finishes.
    for arm in ("P1", "P2"):
        for seed in (0, 1, 2):
            candidate = ledger.register_candidate(
                "exp", arm, seed, {"task_instruction": f"fixture {arm} seed {seed}"}
            ).data
            for _ in range(240):
                ledger.reserve(
                    "exp",
                    arm,
                    seed,
                    candidate["candidate_digest"],
                    "task-0-0",
                    "train",
                    manifest(candidate["candidate_digest"], arm, seed),
                )
            with pytest.raises(LedgerError):
                ledger.reserve(
                    "exp",
                    arm,
                    seed,
                    candidate["candidate_digest"],
                    "task-0-0",
                    "train",
                    manifest(candidate["candidate_digest"], arm, seed),
                )
    assert ledger.counts("exp")["task_executions"] == 1440
    assert ledger.counts("exp")["incomplete_reservations"] == 1440


def test_concurrent_last_search_reservation_accepts_one(ledger):
    from concurrent.futures import ThreadPoolExecutor

    candidate = register(ledger)["candidate_digest"]
    for _ in range(239):
        ledger.reserve(
            "exp", "P1", 0, candidate, "task-0-0", "train", manifest(candidate)
        )

    def attempt():
        try:
            ledger.reserve(
                "exp", "P1", 0, candidate, "task-0-0", "train", manifest(candidate)
            )
            return True
        except LedgerError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: attempt(), range(2))) == [False, True]
    assert ledger.counts("exp")["task_executions"] == 240


def test_feedback_is_arm_seed_scoped_and_scalar_or_typed(ledger):
    for arm, seed in (("P1", 0), ("P1", 1), ("P2", 0)):
        candidate = ledger.register_candidate(
            "exp", arm, seed, {"task_instruction": f"fixture {arm} {seed}"}
        ).data["candidate_digest"]
        attempt = ledger.reserve(
            "exp",
            arm,
            seed,
            candidate,
            "task-0-0",
            "train",
            manifest(candidate, arm, seed),
        )
        ledger.finish(
            attempt,
            score=0,
            status="failure",
            raw_output=f"typed private {arm} {seed}",
            failure_type="stale_or_unsupported_evidence",
        )
    scalar = ledger.feedback("exp", "proposer", arm="P1", seed=0).data
    assert len(scalar["records"]) == 1
    assert scalar["feedback_mode"] == "scalar"
    assert (
        not {
            "raw_output",
            "failure_type",
            "evidence_references",
            "remediation_hypothesis",
        }
        & scalar["records"][0].keys()
    )
    typed = ledger.feedback("exp", "proposer", arm="P2", seed=0).data
    assert len(typed["records"]) == 1
    assert typed["records"][0]["raw_output"] == "typed private P2 0"
    assert typed["records"][0]["evidence_references"]
    with pytest.raises(LedgerError):
        ledger.feedback("exp", "proposer", arm="P0", seed=0)
