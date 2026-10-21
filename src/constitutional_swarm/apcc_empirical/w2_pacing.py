"""Pure controller accounting for W2 windows; none of these records are authority facts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass


def _integer(value: object, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"invalid {name}")
    return value


@dataclass(frozen=True)
class Slot:
    slot_index: int
    chain_index: int
    node_index: int
    scheduled_ns: int
    deadline_ns: int


@dataclass(frozen=True)
class WindowPlan:
    """Explicit pacing policy using bounded-round-robin-16-v1.

    Admission deadlines and window closure are exclusive. The operation SLA starts
    at admission; the drain deadline is duration_ns + drain_ns, inclusive. A plan
    marked qualification merely requests the operation-floor check: it is not
    proof of campaign qualification, provenance, or cold/warm lifecycle coverage.
    """

    duration_ns: int
    scheduled_operations: int
    admission_grace_ns: int
    operation_sla_ns: int
    drain_ns: int
    operation_floor: int
    qualification: bool = False

    def __post_init__(self) -> None:
        for name in (
            "duration_ns",
            "scheduled_operations",
            "admission_grace_ns",
            "operation_sla_ns",
            "operation_floor",
        ):
            _integer(getattr(self, name), name, 1)
        _integer(self.drain_ns, "drain_ns")
        if type(self.qualification) is not bool:
            raise ValueError("invalid qualification")
        if self.scheduled_operations % 100:
            raise ValueError(
                "scheduled operations must contain complete 100-node chains"
            )
        if self.operation_floor > self.scheduled_operations:
            raise ValueError("operation floor exceeds scheduled operations")
        if self.qualification and self.operation_floor < 10_000:
            raise ValueError("qualification operation floor must be at least 10000")

    def slot(self, index: int) -> Slot:
        _integer(index, "slot index")
        if index >= self.scheduled_operations:
            raise ValueError("slot index outside window")
        chains = self.scheduled_operations // 100
        base = (index // 1600) * 16
        width = min(16, chains - base)
        offset = index - base * 100
        scheduled = index * self.duration_ns // self.scheduled_operations
        return Slot(
            index,
            base + offset % width,
            offset // width,
            scheduled,
            min(scheduled + self.admission_grace_ns, self.duration_ns),
        )


@dataclass(frozen=True)
class Accounting:
    scheduled: int
    committed: int
    overloads: int
    late_completions: int
    on_time_commits: int
    max_occupancy: int
    qualified: bool


def verify_accounting(
    plan: WindowPlan,
    records: Sequence[Mapping[str, object]],
    *,
    worker_ids: Sequence[int],
    claimed_counts: Mapping[str, object] | None = None,
    failure_prefix: bool = False,
    slot_hard_ceiling_ns: int | None = None,
) -> Accounting:
    """Reconstruct every denominator and interval from controller-sealed records.

    Caller must separately authenticate the seal, bind each committed record to
    its signed observation, and verify its uncached causal closure. Overload
    reasons are controller reports, never signed authority decisions.
    """
    if type(plan) is not WindowPlan:
        raise ValueError("invalid window plan")
    if len(worker_ids) != 16:
        raise ValueError("exactly 16 workers required")
    for worker in worker_ids:
        _integer(worker, "worker ID", 1)
    if len(set(worker_ids)) != 16:
        raise ValueError("duplicate worker ID")
    if len(records) > plan.scheduled_operations or (
        not failure_prefix and len(records) != plan.scheduled_operations
    ):
        raise ValueError("truncated or extended slot records")
    commits: dict[tuple[int, int], int] = {}
    verified: dict[tuple[int, int], int] = {}
    intervals: dict[int, list[tuple[int, int]]] = {worker: [] for worker in worker_ids}
    events: list[tuple[int, int]] = []
    late = 0
    overloads = 0
    for index, row in enumerate(records):
        expected = asdict(plan.slot(index))
        for name, value in expected.items():
            if _integer(row.get(name), name) != value:
                raise ValueError(f"slot schedule mismatch: {name}")
        chain, node = expected["chain_index"], expected["node_index"]
        predecessor = commits.get((chain, node - 1)) if node else 0
        if row.get("outcome") == "overload":
            if set(row) != set(expected) | {"outcome", "decision_ns", "reason"}:
                raise ValueError("invalid overload fields")
            decision = _integer(row["decision_ns"], "decision_ns")
            if decision < expected["deadline_ns"]:
                raise ValueError("overload before admission deadline")
            reason = row["reason"]
            if reason not in (
                "permit_exhausted",
                "predecessor_uncommitted",
                "window_closed",
                "chain_unavailable",
                "admission_deadline",
            ):
                raise ValueError("invalid overload reason")
            if reason == "predecessor_uncommitted" and (
                not node
                or (predecessor is not None and predecessor < expected["deadline_ns"])
            ):
                raise ValueError("predecessor overload contradicts commit")
            if reason == "window_closed" and decision < plan.duration_ns:
                raise ValueError("window closure precedes boundary")
            overloads += 1
            continue
        if row.get("outcome") != "committed" or set(row) != set(expected) | {
            "outcome",
            "admitted_ns",
            "started_ns",
            "commit_end_ns",
            "end_ns",
            "worker_id",
        }:
            raise ValueError("invalid committed fields")
        admit, start, commit, end, worker = (
            _integer(row[name], name)
            for name in (
                "admitted_ns",
                "started_ns",
                "commit_end_ns",
                "end_ns",
                "worker_id",
            )
        )
        if not expected["scheduled_ns"] <= admit < expected["deadline_ns"]:
            raise ValueError("admission outside slot boundary")
        if not admit <= start <= commit <= end or end == admit:
            raise ValueError("invalid operation interval")
        if predecessor is None or predecessor > admit:
            raise ValueError("successor admitted before predecessor commit")
        if node == 0 and chain >= 16:
            prior_completion = verified.get((chain - 16, 99))
            if prior_completion is None or prior_completion > admit:
                raise ValueError("chain rotation before complete proof verification")
        if worker not in intervals:
            raise ValueError("unknown worker ID")
        intervals[worker].append((start, end))
        events.extend(((admit, 1), (end, -1)))
        commits[chain, node] = commit
        verified[chain, node] = end
        late += int(
            end > admit + plan.operation_sla_ns
            or end > plan.duration_ns + plan.drain_ns
            or (
                slot_hard_ceiling_ns is not None
                and end > expected["scheduled_ns"] + slot_hard_ceiling_ns
            )
        )
    for worker_intervals in intervals.values():
        ordered = sorted(worker_intervals)
        if any(right[0] < left[1] for left, right in zip(ordered, ordered[1:])):
            raise ValueError("overlapping intervals on one worker")
    occupancy = maximum = 0
    for _, delta in sorted(events):
        occupancy += delta
        maximum = max(maximum, occupancy)
        if occupancy < 0 or occupancy > 16:
            raise ValueError("worker permit occupancy exceeds 16")
    committed = len(commits)
    result = Accounting(
        plan.scheduled_operations,
        committed,
        overloads,
        late,
        committed - late,
        maximum,
        plan.qualification and committed - late >= plan.operation_floor and late == 0,
    )
    if claimed_counts is not None:
        expected_counts = asdict(result)
        if set(claimed_counts) != set(expected_counts) or any(
            type(claimed_counts[key]) is not type(value) or claimed_counts[key] != value
            for key, value in expected_counts.items()
        ):
            raise ValueError("forged accounting counters")
    return result
