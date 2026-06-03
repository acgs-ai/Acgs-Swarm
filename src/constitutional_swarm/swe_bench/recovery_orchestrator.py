"""Optional recovery-plane controller for SWE-bench swarm runs.

``SWERecoveryController`` is deliberately separate from ``SwarmCoordinator``.
It observes completed local/official evaluation rows, classifies recoverable
failure signals, and can run policy-capped recovery attempts through an injected
runner.  Baseline rows are never mutated or discarded: recovery produces a
separate attempt log plus a derived ``final_rows`` view for reporting deltas.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RecoveryMode(StrEnum):
    """Recovery execution mode."""

    OFF = "off"
    ADVISORY = "advisory"
    ACTIVE = "active"


class RecoverySignalType(StrEnum):
    """Failure signals the recovery controller can classify."""

    NO_PATCH = "NO_PATCH"
    GENERATION_ERROR = "GENERATION_ERROR"
    AGENT_TIMEOUT = "AGENT_TIMEOUT"
    EMPTY_PATCH = "EMPTY_PATCH"
    PATCH_PARSE_FAILED = "PATCH_PARSE_FAILED"
    PATCH_APPLY_FAILED = "PATCH_APPLY_FAILED"
    TEST_FAILURE = "TEST_FAILURE"
    ENV_NATIVE_BUILD_BLOCKED = "ENV_NATIVE_BUILD_BLOCKED"
    HARNESS_ERROR = "HARNESS_ERROR"
    OFFICIAL_LOCAL_DISAGREEMENT = "OFFICIAL_LOCAL_DISAGREEMENT"


class RecoverySeverity(StrEnum):
    """Relative severity for routing/escalation."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    BLOCKED = "blocked"


class RecoveryActionKind(StrEnum):
    """Policy actions available to the recovery plane."""

    RECOMMEND = "recommend"
    RETRY_SAME = "retry_same"
    REROUTE_AGENT = "reroute_agent"
    REBUILD_WITH_TIMEOUT = "rebuild_with_timeout"
    MARK_BLOCKED = "mark_blocked"
    ESCALATE = "escalate"
    NOOP = "noop"


@dataclass(frozen=True)
class RecoverySignal:
    """Classified recovery signal for one SWE-bench instance."""

    type: RecoverySignalType
    severity: RecoverySeverity
    instance_id: str
    attempt_id: str
    source: str
    stage: str
    error_class: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RecoveryAction:
    """A policy decision for a recovery signal."""

    kind: RecoveryActionKind
    reason: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RecoveryPolicy:
    """Policy caps and action toggles for ``SWERecoveryController``."""

    mode: RecoveryMode = RecoveryMode.OFF
    per_instance_attempt_cap: int = 1
    global_attempt_cap: int = 10
    allowed_actions: frozenset[RecoveryActionKind] | None = None
    timeout_multiplier: float = 2.0
    reroute_enabled: bool = True
    blocked_patterns: tuple[str, ...] = (
        "native build incompatibility",
        "requires rust",
        "requires cargo",
        "failed building wheel",
    )

    def __post_init__(self) -> None:
        if isinstance(self.mode, str):
            object.__setattr__(self, "mode", RecoveryMode(self.mode))
        if self.per_instance_attempt_cap < 0:
            raise ValueError("per_instance_attempt_cap must be >= 0")
        if self.global_attempt_cap < 0:
            raise ValueError("global_attempt_cap must be >= 0")
        if self.timeout_multiplier <= 0:
            raise ValueError("timeout_multiplier must be > 0")


@dataclass(frozen=True)
class RecoveryAttempt:
    """Audit record for an advisory or active recovery decision."""

    attempt_id: str
    parent_attempt_id: str
    trigger_signal: RecoverySignal
    action: RecoveryAction
    input_row: dict[str, Any]
    output_row: dict[str, Any] | None = None
    output_status: str = "not_run"


@dataclass(frozen=True)
class RecoveryBundle:
    """Complete recovery report with immutable baseline and derived final rows."""

    baseline_rows: list[dict[str, Any]]
    recovery_attempts: list[RecoveryAttempt]
    final_rows: list[dict[str, Any]]
    baseline_summary: dict[str, Any]
    recovered_summary: dict[str, Any]
    delta: dict[str, Any]
    blocked_count: int = 0
    escalated_count: int = 0


AttemptRunner = Callable[[dict[str, Any], RecoveryAction, int], dict[str, Any]]


class SWERecoveryController:
    """Classify and optionally recover failed SWE-bench swarm rows.

    The controller is recovery-plane only: it does not replace swarm routing,
    CRDT settlement, constitutional voting, or the local/official harnesses.
    Active recovery is injected through ``attempt_runner`` so tests and scripts
    can choose how to retry, reroute, or rebuild without this module depending
    on a specific agent backend.
    """

    def __init__(
        self,
        *,
        policy: RecoveryPolicy | None = None,
        attempt_runner: AttemptRunner | None = None,
    ) -> None:
        self.policy = policy or RecoveryPolicy()
        self.attempt_runner = attempt_runner

    def run(
        self,
        baseline_rows: Iterable[Mapping[str, Any]],
        *,
        official_resolved_ids: Iterable[str] | None = None,
        official_unresolved_ids: Iterable[str] | None = None,
        official_error_ids: Iterable[str] | None = None,
    ) -> RecoveryBundle:
        """Classify rows and return an advisory/active recovery bundle.

        ``RecoveryMode.OFF`` is inert: no signals are classified, no attempts are
        recorded, and ``final_rows`` is a deep copy of ``baseline_rows``.
        """
        baseline = [dict(row) for row in baseline_rows]
        final_rows = deepcopy(baseline)
        baseline_summary = _summarize_rows(baseline)

        if self.policy.mode is RecoveryMode.OFF:
            return _bundle(
                baseline_rows=baseline,
                final_rows=final_rows,
                attempts=[],
                baseline_summary=baseline_summary,
            )

        official_status = _official_status_by_id(
            resolved_ids=official_resolved_ids,
            unresolved_ids=official_unresolved_ids,
            error_ids=official_error_ids,
        )
        attempts: list[RecoveryAttempt] = []
        global_active_attempts = 0
        per_instance_active_attempts: dict[str, int] = {}

        for index, row in enumerate(baseline):
            instance_id = _instance_id(row)
            signals = self.classify_row(
                row,
                official_status=official_status.get(instance_id),
            )
            if not signals:
                continue

            signal = signals[0]
            action = self.recommend(signal)
            parent_attempt_id = _row_attempt_id(row)
            attempt_id = f"{parent_attempt_id}:recovery-1"

            if self.policy.mode is RecoveryMode.ADVISORY:
                recommended = action
                action = RecoveryAction(
                    RecoveryActionKind.RECOMMEND,
                    reason=recommended.reason,
                    params={
                        **recommended.params,
                        "recommended_action": recommended.kind.value,
                    },
                )
                attempts.append(
                    RecoveryAttempt(
                        attempt_id=attempt_id,
                        parent_attempt_id=parent_attempt_id,
                        trigger_signal=signal,
                        action=action,
                        input_row=deepcopy(row),
                        output_status="advisory",
                    )
                )
                continue

            if action.kind in {RecoveryActionKind.MARK_BLOCKED, RecoveryActionKind.ESCALATE}:
                attempts.append(
                    RecoveryAttempt(
                        attempt_id=attempt_id,
                        parent_attempt_id=parent_attempt_id,
                        trigger_signal=signal,
                        action=action,
                        input_row=deepcopy(row),
                        output_status=action.kind.value,
                    )
                )
                continue

            if action.kind is RecoveryActionKind.NOOP:
                attempts.append(
                    RecoveryAttempt(
                        attempt_id=attempt_id,
                        parent_attempt_id=parent_attempt_id,
                        trigger_signal=signal,
                        action=action,
                        input_row=deepcopy(row),
                        output_status="noop",
                    )
                )
                continue

            if not self._action_allowed(action.kind):
                attempts.append(
                    RecoveryAttempt(
                        attempt_id=attempt_id,
                        parent_attempt_id=parent_attempt_id,
                        trigger_signal=signal,
                        action=RecoveryAction(
                            RecoveryActionKind.ESCALATE,
                            reason=f"action {action.kind.value} is not allowed by policy",
                            params={"blocked_action": action.kind.value},
                        ),
                        input_row=deepcopy(row),
                        output_status="action_not_allowed",
                    )
                )
                continue

            if global_active_attempts >= self.policy.global_attempt_cap:
                attempts.append(
                    RecoveryAttempt(
                        attempt_id=attempt_id,
                        parent_attempt_id=parent_attempt_id,
                        trigger_signal=signal,
                        action=RecoveryAction(
                            RecoveryActionKind.ESCALATE,
                            reason="global recovery attempt cap exhausted",
                        ),
                        input_row=deepcopy(row),
                        output_status="global_cap_exhausted",
                    )
                )
                continue

            used_for_instance = per_instance_active_attempts.get(instance_id, 0)
            if used_for_instance >= self.policy.per_instance_attempt_cap:
                attempts.append(
                    RecoveryAttempt(
                        attempt_id=attempt_id,
                        parent_attempt_id=parent_attempt_id,
                        trigger_signal=signal,
                        action=RecoveryAction(
                            RecoveryActionKind.ESCALATE,
                            reason="per-instance recovery attempt cap exhausted",
                        ),
                        input_row=deepcopy(row),
                        output_status="per_instance_cap_exhausted",
                    )
                )
                continue

            if self.attempt_runner is None:
                attempts.append(
                    RecoveryAttempt(
                        attempt_id=attempt_id,
                        parent_attempt_id=parent_attempt_id,
                        trigger_signal=signal,
                        action=RecoveryAction(
                            RecoveryActionKind.ESCALATE,
                            reason="active recovery requires an attempt_runner",
                        ),
                        input_row=deepcopy(row),
                        output_status="missing_runner",
                    )
                )
                continue

            global_active_attempts += 1
            attempt_index = used_for_instance + 1
            per_instance_active_attempts[instance_id] = attempt_index
            try:
                output = dict(self.attempt_runner(deepcopy(row), action, attempt_index))
                final_rows[index] = output
                output_status = "resolved" if bool(output.get("resolved")) else "unresolved"
                attempts.append(
                    RecoveryAttempt(
                        attempt_id=f"{parent_attempt_id}:recovery-{attempt_index}",
                        parent_attempt_id=parent_attempt_id,
                        trigger_signal=signal,
                        action=action,
                        input_row=deepcopy(row),
                        output_row=deepcopy(output),
                        output_status=output_status,
                    )
                )
            except Exception as exc:  # pragma: no cover - defensive safety path
                attempts.append(
                    RecoveryAttempt(
                        attempt_id=f"{parent_attempt_id}:recovery-{attempt_index}",
                        parent_attempt_id=parent_attempt_id,
                        trigger_signal=signal,
                        action=RecoveryAction(
                            RecoveryActionKind.ESCALATE,
                            reason="recovery attempt runner failed",
                            params={"error_class": type(exc).__name__},
                        ),
                        input_row=deepcopy(row),
                        output_status="runner_error",
                    )
                )

        return _bundle(
            baseline_rows=baseline,
            final_rows=final_rows,
            attempts=attempts,
            baseline_summary=baseline_summary,
        )

    def classify_row(
        self,
        row: Mapping[str, Any],
        *,
        official_status: str | None = None,
    ) -> list[RecoverySignal]:
        """Return recovery signals for a single evaluation row."""
        instance_id = _instance_id(row)
        attempt_id = _row_attempt_id(row)
        stage = str(row.get("stage") or "unknown")
        error = _error_text(row)
        signals: list[RecoverySignal] = []

        if official_status and _local_official_disagree(row, official_status):
            signals.append(
                RecoverySignal(
                    type=RecoverySignalType.OFFICIAL_LOCAL_DISAGREEMENT,
                    severity=RecoverySeverity.ERROR,
                    instance_id=instance_id,
                    attempt_id=attempt_id,
                    source="official_harness",
                    stage=stage,
                    error_class=official_status,
                    details={
                        "official_status": official_status,
                        "local_resolved": bool(row.get("resolved")),
                    },
                )
            )

        if bool(row.get("resolved")):
            return signals

        if (
            stage == "env_native_build_blocked"
            or self._matches_blocked_pattern(row)
            or row.get("native_build_blocked")
        ):
            signals.append(
                _signal(
                    RecoverySignalType.ENV_NATIVE_BUILD_BLOCKED,
                    RecoverySeverity.BLOCKED,
                    row,
                    source="local_harness",
                    error_class="native-build-incompatibility",
                )
            )
            return signals

        patch_generated = bool(row.get("patch_generated"))
        patch = str(row.get("patch") or "")
        if not patch_generated:
            if "timeout" in error:
                signal_type = RecoverySignalType.AGENT_TIMEOUT
            elif error in {"", "no_patch", "none"}:
                signal_type = RecoverySignalType.NO_PATCH
            else:
                signal_type = RecoverySignalType.GENERATION_ERROR
            signals.append(
                _signal(
                    signal_type,
                    RecoverySeverity.ERROR,
                    row,
                    source="agent",
                    error_class=str(row.get("error") or signal_type.value),
                )
            )
            return signals

        if not patch.strip():
            signals.append(
                _signal(
                    RecoverySignalType.EMPTY_PATCH,
                    RecoverySeverity.ERROR,
                    row,
                    source="agent",
                    error_class="empty_patch",
                )
            )
            return signals

        if "parse" in stage or "parse" in error:
            signals.append(
                _signal(
                    RecoverySignalType.PATCH_PARSE_FAILED,
                    RecoverySeverity.ERROR,
                    row,
                    source="local_harness",
                    error_class="patch_parse_failed",
                )
            )
            return signals

        if stage == "apply" or not bool(row.get("applied")):
            signals.append(
                _signal(
                    RecoverySignalType.PATCH_APPLY_FAILED,
                    RecoverySeverity.ERROR,
                    row,
                    source="local_harness",
                    error_class="patch_apply_failed",
                )
            )
            return signals

        if stage == "tests":
            signals.append(
                _signal(
                    RecoverySignalType.TEST_FAILURE,
                    RecoverySeverity.WARNING,
                    row,
                    source="local_harness",
                    error_class="test_failure",
                )
            )
            return signals

        if stage not in {"done", "unknown"} or error:
            signals.append(
                _signal(
                    RecoverySignalType.HARNESS_ERROR,
                    RecoverySeverity.ERROR,
                    row,
                    source="local_harness",
                    error_class=str(row.get("error") or stage),
                )
            )

        return signals

    def recommend(self, signal: RecoverySignal) -> RecoveryAction:
        """Return the policy action for a signal."""
        match signal.type:
            case RecoverySignalType.ENV_NATIVE_BUILD_BLOCKED:
                return RecoveryAction(
                    RecoveryActionKind.MARK_BLOCKED,
                    reason="environment failure is classified as an external native-build blocker",
                    params={"signal": signal.type.value},
                )
            case RecoverySignalType.AGENT_TIMEOUT:
                return RecoveryAction(
                    RecoveryActionKind.REBUILD_WITH_TIMEOUT,
                    reason="agent timeout can be retried with a bounded timeout multiplier",
                    params={"timeout_multiplier": self.policy.timeout_multiplier},
                )
            case (
                RecoverySignalType.NO_PATCH
                | RecoverySignalType.GENERATION_ERROR
                | RecoverySignalType.EMPTY_PATCH
                | RecoverySignalType.PATCH_PARSE_FAILED
            ):
                return RecoveryAction(
                    RecoveryActionKind.RETRY_SAME,
                    reason="generation/patch-shape failure is eligible for a same-agent retry",
                    params={"signal": signal.type.value},
                )
            case RecoverySignalType.PATCH_APPLY_FAILED | RecoverySignalType.TEST_FAILURE:
                if self.policy.reroute_enabled:
                    return RecoveryAction(
                        RecoveryActionKind.REROUTE_AGENT,
                        reason="patch applied poorly or tests failed; try an alternate agent route",
                        params={"signal": signal.type.value},
                    )
                return RecoveryAction(
                    RecoveryActionKind.RETRY_SAME,
                    reason="reroute disabled; retrying same recovery lane",
                    params={"signal": signal.type.value},
                )
            case RecoverySignalType.OFFICIAL_LOCAL_DISAGREEMENT | RecoverySignalType.HARNESS_ERROR:
                return RecoveryAction(
                    RecoveryActionKind.ESCALATE,
                    reason="requires human/toolchain review before automatic recovery",
                    params={"signal": signal.type.value},
                )
        return RecoveryAction(RecoveryActionKind.NOOP, reason="no recovery action available")

    def _action_allowed(self, action: RecoveryActionKind) -> bool:
        allowed = self.policy.allowed_actions
        return allowed is None or action in allowed

    def _matches_blocked_pattern(self, row: Mapping[str, Any]) -> bool:
        text = " ".join(
            str(row.get(key) or "")
            for key in ("stage", "error", "log_tail")
        ).lower()
        return any(pattern.lower() in text for pattern in self.policy.blocked_patterns)


def _signal(
    signal_type: RecoverySignalType,
    severity: RecoverySeverity,
    row: Mapping[str, Any],
    *,
    source: str,
    error_class: str | None,
) -> RecoverySignal:
    return RecoverySignal(
        type=signal_type,
        severity=severity,
        instance_id=_instance_id(row),
        attempt_id=_row_attempt_id(row),
        source=source,
        stage=str(row.get("stage") or "unknown"),
        error_class=error_class,
        details={
            "error": row.get("error"),
            "patch_generated": bool(row.get("patch_generated")),
            "applied": bool(row.get("applied")),
            "resolved": bool(row.get("resolved")),
        },
    )


def _bundle(
    *,
    baseline_rows: list[dict[str, Any]],
    final_rows: list[dict[str, Any]],
    attempts: list[RecoveryAttempt],
    baseline_summary: dict[str, Any],
) -> RecoveryBundle:
    recovered_summary = _summarize_rows(final_rows)
    return RecoveryBundle(
        baseline_rows=deepcopy(baseline_rows),
        recovery_attempts=attempts,
        final_rows=deepcopy(final_rows),
        baseline_summary=baseline_summary,
        recovered_summary=recovered_summary,
        delta={
            key: recovered_summary[key] - baseline_summary[key]
            for key in ("patch_generated", "applied", "resolved", "native_build_blocked")
        },
        blocked_count=sum(
            1 for attempt in attempts if attempt.action.kind is RecoveryActionKind.MARK_BLOCKED
        ),
        escalated_count=sum(
            1 for attempt in attempts if attempt.action.kind is RecoveryActionKind.ESCALATE
        ),
    )


def _summarize_rows(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    patch_generated = sum(1 for row in rows if row.get("patch_generated"))
    applied = sum(1 for row in rows if row.get("applied"))
    resolved = sum(1 for row in rows if row.get("resolved"))
    native_build_blocked = sum(1 for row in rows if row.get("native_build_blocked"))
    return {
        "instances": total,
        "patch_generated": patch_generated,
        "applied": applied,
        "resolved": resolved,
        "native_build_blocked": native_build_blocked,
        "patch_rate": patch_generated / total if total else 0.0,
        "apply_rate": applied / total if total else 0.0,
        "resolve_rate": resolved / total if total else 0.0,
    }


def _official_status_by_id(
    *,
    resolved_ids: Iterable[str] | None,
    unresolved_ids: Iterable[str] | None,
    error_ids: Iterable[str] | None,
) -> dict[str, str]:
    status: dict[str, str] = {}
    for instance_id in resolved_ids or ():
        status[str(instance_id)] = "resolved"
    for instance_id in unresolved_ids or ():
        status[str(instance_id)] = "unresolved"
    for instance_id in error_ids or ():
        status[str(instance_id)] = "error"
    return status


def _local_official_disagree(row: Mapping[str, Any], official_status: str) -> bool:
    local_resolved = bool(row.get("resolved"))
    if official_status == "resolved":
        return not local_resolved
    if official_status in {"unresolved", "error"}:
        return local_resolved
    return False


def _error_text(row: Mapping[str, Any]) -> str:
    error = row.get("error")
    if error is None:
        patch_metadata = row.get("patch_metadata") or {}
        if isinstance(patch_metadata, Mapping):
            error = patch_metadata.get("error")
    return str(error or "").strip().lower()


def _instance_id(row: Mapping[str, Any]) -> str:
    return str(row.get("instance_id") or "unknown")


def _row_attempt_id(row: Mapping[str, Any]) -> str:
    raw = row.get("attempt_id") or row.get("run_id") or _instance_id(row)
    return str(raw)
