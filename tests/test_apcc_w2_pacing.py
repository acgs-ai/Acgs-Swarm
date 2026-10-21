"""Controller schedule reconstruction never substitutes for authority verification."""

from dataclasses import asdict, replace

import pytest

from constitutional_swarm.apcc_empirical.w2_pacing import WindowPlan, verify_accounting


def plan(count=200):
    return WindowPlan(count * 10, count, 10, 100, 100, count)


def records(policy):
    return [
        {
            **asdict(policy.slot(i)),
            "outcome": "committed",
            "admitted_ns": i * 10,
            "started_ns": i * 10,
            "commit_end_ns": i * 10 + 1,
            "end_ns": i * 10 + 2,
            "worker_id": i % 16 + 1,
        }
        for i in range(policy.scheduled_operations)
    ]


def audit(policy, rows, **kwargs):
    return verify_accounting(policy, rows, worker_ids=list(range(1, 17)), **kwargs)


def test_exact_mapping_including_last_partial_batch():
    policy = plan(10000)
    assert (policy.slot(1599).chain_index, policy.slot(1599).node_index) == (15, 99)
    assert (policy.slot(1600).chain_index, policy.slot(1600).node_index) == (16, 0)
    assert (policy.slot(9600).chain_index, policy.slot(9600).node_index) == (96, 0)
    assert (policy.slot(9999).chain_index, policy.slot(9999).node_index) == (99, 99)
    assert policy.slot(9999).deadline_ns == policy.duration_ns


def test_functional_and_qualification_floor_are_separate():
    small = plan()
    assert not audit(small, records(small)).qualified
    with pytest.raises(ValueError, match="10000"):
        replace(small, qualification=True)
    full = replace(plan(10000), qualification=True)
    result = audit(full, records(full))
    assert result.qualified and result.committed == result.on_time_commits == 10000
    assert audit(full, records(full), claimed_counts=asdict(result)) == result


def test_deadline_rejection_does_not_claim_predecessor_authority_state():
    policy = plan(100)
    rows = records(policy)
    # A controller may miss publication of an already committed predecessor.
    # The generic deadline reason must not contradict the signed commit time.
    for index in range(1, 100):
        rows[index] = {
            **asdict(policy.slot(index)),
            "outcome": "overload",
            "decision_ns": policy.slot(index).deadline_ns,
            "reason": "admission_deadline",
        }
    result = audit(policy, rows)
    assert result.committed == 1 and result.overloads == 99


@pytest.mark.parametrize(
    "field,value",
    [
        ("duration_ns", True),
        ("scheduled_operations", 101),
        ("admission_grace_ns", 0),
        ("operation_sla_ns", -1),
        ("drain_ns", -1),
        ("operation_floor", 201),
        ("qualification", 1),
    ],
)
def test_plan_rejects_noncanonical_values(field, value):
    with pytest.raises(ValueError):
        replace(plan(), **{field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("chain_index", 1),
        ("node_index", 1),
        ("scheduled_ns", 1),
        ("deadline_ns", 11),
        ("admitted_ns", 10),
        ("worker_id", True),
    ],
)
def test_spliced_or_skewed_slot_rejected(field, value):
    policy = plan()
    rows = records(policy)
    rows[0][field] = value
    with pytest.raises(ValueError):
        audit(policy, rows)


def test_truncated_slots_and_forged_counts_rejected():
    policy = plan()
    rows = records(policy)
    with pytest.raises(ValueError, match="truncated"):
        audit(policy, rows[:-1])
    counts = asdict(audit(policy, rows))
    counts["overloads"] = 1
    with pytest.raises(ValueError, match="forged"):
        audit(policy, rows, claimed_counts=counts)


def test_lateness_and_drain_are_reconstructed():
    policy = plan()
    rows = records(policy)
    rows[-1]["end_ns"] = policy.duration_ns + policy.drain_ns + 1
    result = audit(policy, rows)
    assert result.late_completions == 1 and result.on_time_commits == 199
    policy = replace(policy, operation_sla_ns=1)
    assert audit(policy, records(policy)).late_completions == 200


def test_causal_admission_and_worker_overlap_rejected():
    policy = plan()
    rows = records(policy)
    rows[0]["commit_end_ns"] = rows[0]["end_ns"] = 21
    with pytest.raises(ValueError, match="predecessor"):
        audit(policy, rows)
    rows = records(policy)
    rows[0]["end_ns"] = 161
    with pytest.raises(ValueError, match="overlapping"):
        audit(policy, rows)


def test_overload_tail_counts_and_missing_predecessor():
    policy = plan(100)
    rows = records(policy)
    for i in range(50, 100):
        rows[i] = {
            **asdict(policy.slot(i)),
            "outcome": "overload",
            "decision_ns": policy.slot(i).deadline_ns,
            "reason": "permit_exhausted" if i == 50 else "predecessor_uncommitted",
        }
    result = audit(policy, rows)
    assert (result.committed, result.overloads) == (50, 50)
    rows[-1] = records(policy)[-1]
    with pytest.raises(ValueError, match="predecessor"):
        audit(policy, rows)


def test_permits_cover_queued_work_through_verification():
    policy = plan(1700)
    rows = records(policy)
    # Queue seventeen admitted operations, starting each worker only after its
    # previous execution ends. Worker intervals alone would miss this violation.
    for i in range(17):
        rows[i].update(
            started_ns=1000 + i * 3, commit_end_ns=1001 + i * 3, end_ns=1002 + i * 3
        )
    # Remaining slots are rejected so their causal admission cannot mask occupancy.
    for i in range(17, 1700):
        rows[i] = {
            **asdict(policy.slot(i)),
            "outcome": "overload",
            "decision_ns": policy.slot(i).deadline_ns,
            "reason": "chain_unavailable",
        }
    # Slot 16 is a successor; let root commit before it admits, but retain its
    # permit while verification runs.
    rows[0].update(started_ns=0, commit_end_ns=1, end_ns=1000)
    with pytest.raises(ValueError, match="occupancy"):
        audit(policy, rows)


def test_next_batch_waits_for_complete_verification_of_previous_lane():
    policy = plan(1700)
    rows = records(policy)
    rows[1584]["end_ns"] = rows[1600]["admitted_ns"] + 1
    with pytest.raises(ValueError, match="rotation"):
        audit(policy, rows)
