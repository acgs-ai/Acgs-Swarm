from __future__ import annotations

from constitutional_swarm.swe_bench.recovery_orchestrator import (
    RecoveryActionKind,
    RecoveryMode,
    RecoveryPolicy,
    RecoverySignalType,
    SWERecoveryController,
)


def _row(instance_id: str, **overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "instance_id": instance_id,
        "repo": "demo/repo",
        "patch_generated": True,
        "applied": True,
        "resolved": False,
        "stage": "tests",
        "error": "failing tests",
        "log_tail": "",
        "patch": "diff --git a/file.py b/file.py\n+fix\n",
    }
    row.update(overrides)
    return row


def test_off_mode_is_inert_and_preserves_baseline_rows() -> None:
    baseline = [_row("repo-1", patch_generated=False, applied=False, stage="patch_generation")]
    calls: list[object] = []

    controller = SWERecoveryController(
        policy=RecoveryPolicy(mode=RecoveryMode.OFF),
        attempt_runner=lambda row, action, attempt_index: calls.append(action) or row,
    )

    bundle = controller.run(baseline)

    assert bundle.baseline_rows == baseline
    assert bundle.final_rows == baseline
    assert bundle.recovery_attempts == []
    assert calls == []
    assert bundle.delta["resolved"] == 0


def test_advisory_mode_classifies_and_recommends_without_rerun() -> None:
    baseline = [
        _row(
            "repo-no-patch",
            patch_generated=False,
            applied=False,
            stage="patch_generation",
            error="no_patch",
            patch="",
        ),
        _row("repo-tests", stage="tests", resolved=False),
    ]
    calls: list[object] = []
    controller = SWERecoveryController(
        policy=RecoveryPolicy(mode=RecoveryMode.ADVISORY),
        attempt_runner=lambda row, action, attempt_index: calls.append(action) or row,
    )

    bundle = controller.run(baseline)

    assert [a.trigger_signal.type for a in bundle.recovery_attempts] == [
        RecoverySignalType.NO_PATCH,
        RecoverySignalType.TEST_FAILURE,
    ]
    assert {a.action.kind for a in bundle.recovery_attempts} == {RecoveryActionKind.RECOMMEND}
    assert bundle.final_rows == baseline
    assert calls == []


def test_active_mode_records_attempt_and_reports_recovered_delta() -> None:
    baseline = [
        _row("repo-timeout", patch_generated=False, applied=False, error="timeout", patch="")
    ]

    def recover(row: dict[str, object], action: object, attempt_index: int) -> dict[str, object]:
        assert attempt_index == 1
        return {**row, "patch_generated": True, "applied": True, "resolved": True, "stage": "done"}

    controller = SWERecoveryController(
        policy=RecoveryPolicy(mode=RecoveryMode.ACTIVE),
        attempt_runner=recover,
    )

    bundle = controller.run(baseline)

    assert baseline[0]["resolved"] is False
    assert bundle.final_rows[0]["resolved"] is True
    assert len(bundle.recovery_attempts) == 1
    attempt = bundle.recovery_attempts[0]
    assert attempt.action.kind == RecoveryActionKind.REBUILD_WITH_TIMEOUT
    assert attempt.output_status == "resolved"
    assert bundle.baseline_summary["resolved"] == 0
    assert bundle.recovered_summary["resolved"] == 1
    assert bundle.delta["resolved"] == 1


def test_active_mode_enforces_global_attempt_cap() -> None:
    baseline = [
        _row("repo-1", patch_generated=False, applied=False, error="timeout", patch=""),
        _row("repo-2", patch_generated=False, applied=False, error="timeout", patch=""),
    ]
    calls: list[str] = []

    def recover(row: dict[str, object], action: object, attempt_index: int) -> dict[str, object]:
        calls.append(str(row["instance_id"]))
        return {**row, "patch_generated": True, "applied": True, "resolved": True, "stage": "done"}

    controller = SWERecoveryController(
        policy=RecoveryPolicy(mode=RecoveryMode.ACTIVE, global_attempt_cap=1),
        attempt_runner=recover,
    )

    bundle = controller.run(baseline)

    assert calls == ["repo-1"]
    assert [row["resolved"] for row in bundle.final_rows] == [True, False]
    assert len(bundle.recovery_attempts) == 2
    assert bundle.recovery_attempts[1].action.kind == RecoveryActionKind.ESCALATE
    assert bundle.recovery_attempts[1].output_status == "global_cap_exhausted"


def test_native_build_blocker_is_marked_blocked_without_runner() -> None:
    baseline = [
        _row(
            "repo-native",
            stage="env_native_build_blocked",
            native_build_blocked=True,
            error="patch applied, env blocked by native build incompatibility",
        )
    ]
    calls: list[object] = []
    controller = SWERecoveryController(
        policy=RecoveryPolicy(mode=RecoveryMode.ACTIVE),
        attempt_runner=lambda row, action, attempt_index: calls.append(action) or row,
    )

    bundle = controller.run(baseline)

    assert calls == []
    assert bundle.blocked_count == 1
    assert bundle.recovery_attempts[0].trigger_signal.type == (
        RecoverySignalType.ENV_NATIVE_BUILD_BLOCKED
    )
    assert bundle.recovery_attempts[0].action.kind == RecoveryActionKind.MARK_BLOCKED


def test_official_local_disagreement_is_escalated() -> None:
    baseline = [_row("repo-disagree", resolved=False, stage="done")]
    controller = SWERecoveryController(policy=RecoveryPolicy(mode=RecoveryMode.ADVISORY))

    bundle = controller.run(baseline, official_resolved_ids={"repo-disagree"})

    assert bundle.recovery_attempts[0].trigger_signal.type == (
        RecoverySignalType.OFFICIAL_LOCAL_DISAGREEMENT
    )
    assert bundle.recovery_attempts[0].action.kind == RecoveryActionKind.RECOMMEND
    assert bundle.recovery_attempts[0].action.params["recommended_action"] == "escalate"
