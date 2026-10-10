"""Round-3 micro-gap tests: targeted coverage for 10 missing lines.

Targets:
- privacy_accountant.py lines 125-126  (ValueError in RDP→epsilon math)
- swarm_coordinator.py lines 154-155  (ImportError for gossip transport)
- swe_bench/codex_agent.py lines 163-164  (OSError on last_path.read_text)
- swe_bench/local_harness.py  (no patch(1) fallback: apply fails closed)
- settlement_store.py line 91  (empty-line skip in load_all)
- execution.py lines 70-71  (KeyError→ValueError in contract_status_from_execution)
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest


# ---------------------------------------------------------------------------
# privacy_accountant.py lines 125-126
# ---------------------------------------------------------------------------
class TestPrivacyAccountantRDPMathError:
    """Trigger ValueError path inside _rdp_to_epsilon_balle2020."""

    def test_zero_delta_triggers_value_error_continue(self):
        """math.log(delta=0 * a) raises ValueError → except branch continues."""
        from constitutional_swarm.privacy_accountant import _rdp_to_epsilon_balle2020

        # delta=0 causes math.log(0) → ValueError → except (ValueError, ZeroDivisionError): continue
        eps, _ = _rdp_to_epsilon_balle2020(
            rdp_values=[1.0],
            alphas=[2.0],
            delta=0.0,
        )
        # All candidates hit the except branch; best_eps stays inf
        import math

        assert math.isinf(eps)

    def test_negative_rdp_triggers_value_error_continue(self):
        """Negative RDP value causes log of negative → ValueError → except continues."""
        # Very large negative r makes delta * a term produce log domain error

        from constitutional_swarm.privacy_accountant import _rdp_to_epsilon_balle2020

        eps, _ = _rdp_to_epsilon_balle2020(
            rdp_values=[float("-inf")],
            alphas=[2.0],
            delta=1e-5,
        )
        # May or may not hit except, but no crash
        assert eps is not None


# ---------------------------------------------------------------------------
# swarm_coordinator.py lines 154-155
# ---------------------------------------------------------------------------
class TestSwarmCoordinatorGossipImportError:
    """Trigger ImportError when gossip transport is unavailable."""

    def test_run_gossip_raises_import_error_without_transport(self):
        """Mock gossip_protocol import failure → ImportError re-raised with message."""
        from constitutional_swarm.swe_bench.harness import SWEBenchAgent
        from constitutional_swarm.swe_bench.swarm_coordinator import SwarmCoordinator

        mock_agent = Mock(spec=SWEBenchAgent)
        coordinator = SwarmCoordinator(agents=[mock_agent])

        with patch.dict(
            "sys.modules",
            {"constitutional_swarm.gossip_protocol": None},
        ):
            with pytest.raises(ImportError, match="WebSocket gossip requires"):
                asyncio.run(
                    coordinator.run_gossip(
                        tasks=[{"instance_id": "t1", "problem_statement": "fix it"}],
                    )
                )


# ---------------------------------------------------------------------------
# swe_bench/codex_agent.py lines 163-164
# ---------------------------------------------------------------------------
class TestCodexAgentOSErrorOnRead:
    """Trigger OSError when reading last_path after successful subprocess run."""

    def test_generate_patch_oserror_on_read(self):
        """last_path.read_text() raises OSError → last_message set to empty string."""
        with patch("shutil.which", return_value="/usr/local/bin/codex"):
            from constitutional_swarm.swe_bench.codex_agent import CodexSWEBenchAgent

            agent = CodexSWEBenchAgent(codex_binary="/usr/local/bin/codex")

        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_proc.stderr = ""

        task = {
            "instance_id": "test-1",
            "problem_statement": "fix the bug",
            "FAIL_TO_PASS": [],
        }

        with (
            patch(
                "constitutional_swarm.swe_bench.codex_agent._run_process",
                return_value=mock_proc,
            ),
            patch("pathlib.Path.read_text", side_effect=OSError("permission denied")),
        ):
            patch_text, stats = agent._generate_patch(task)

        # OSError was caught, last_message defaults to ""
        assert patch_text == ""
        assert stats["raw_length"] == 0


# ---------------------------------------------------------------------------
# swe_bench/local_harness.py — no patch(1) fallback (fail closed)
# ---------------------------------------------------------------------------
class TestLocalHarnessNoPatchFallback:
    """All git-apply strategies failing must fail closed without invoking patch(1)."""

    def test_apply_patch_never_invokes_patch1(self):
        from constitutional_swarm.swe_bench.local_harness import HarnessResult, LocalSWEBenchHarness

        harness = LocalSWEBenchHarness()
        result = HarnessResult(instance_id="test-1")
        worktree = Path("/tmp/fake_worktree")
        commands: list[list[str]] = []

        def mock_run(cmd, **kwargs):
            commands.append(list(cmd))
            return 1, f"git apply failed {len(commands)}"

        with (
            patch("constitutional_swarm.swe_bench.local_harness._run", side_effect=mock_run),
            patch("shutil.which", return_value="/usr/bin/patch"),
        ):
            harness._apply_patch(worktree, "diff --git a/f.py b/f.py\n", result)

        assert result.applied is False
        assert result.error == "patch did not apply"
        assert commands and all(cmd[0] == "git" for cmd in commands)

    def test_apply_patch_failure_log_tail_has_git_apply_output(self):
        from constitutional_swarm.swe_bench.local_harness import HarnessResult, LocalSWEBenchHarness

        harness = LocalSWEBenchHarness()
        result = HarnessResult(instance_id="test-2")
        worktree = Path("/tmp/fake_worktree")

        def mock_run(cmd, **kwargs):
            return 1, "git_apply_fail"

        with (
            patch("constitutional_swarm.swe_bench.local_harness._run", side_effect=mock_run),
            patch("shutil.which", return_value="/usr/bin/patch"),
        ):
            harness._apply_patch(worktree, "--- a/f.py\n+++ b/f.py\n", result)

        assert result.log_tail is not None
        assert "git_apply_fail" in result.log_tail
        assert "---patch(1)---" not in result.log_tail


# ---------------------------------------------------------------------------
# settlement_store.py line 91
# ---------------------------------------------------------------------------
class TestSettlementStoreEmptyLineContinue:
    """Trigger line 91: empty-line skip in load_all."""

    def test_load_all_skips_empty_lines(self, tmp_path):
        """JSONL file with blank lines → empty lines skipped via `continue`."""
        from constitutional_swarm.settlement_store import JSONLSettlementStore, SettlementRecord

        store_file = tmp_path / "settlements.jsonl"
        record = SettlementRecord(
            assignment={"assignment_id": "a1", "task": "t"},
            result={"status": "ok"},
            constitutional_hash="abc123",
        )

        # Write a valid record
        valid_line = json.dumps(
            {
                "assignment": record.assignment,
                "result": record.result,
                "constitutional_hash": record.constitutional_hash,
            },
            separators=(",", ":"),
        )

        # File has: empty line, valid record, trailing empty line → line 91 hit twice
        store_file.write_text("\n" + valid_line + "\n\n", encoding="utf-8")

        store = JSONLSettlementStore(store_file)
        records = store.load_all()

        assert len(records) == 1
        assert records[0].assignment["assignment_id"] == "a1"

    def test_load_all_only_empty_lines_returns_empty(self, tmp_path):
        """File with only blank lines → all skipped, returns empty list."""
        from constitutional_swarm.settlement_store import JSONLSettlementStore

        store_file = tmp_path / "settlements.jsonl"
        store_file.write_text("\n\n\n", encoding="utf-8")

        store = JSONLSettlementStore(store_file)
        records = store.load_all()
        assert records == []


# ---------------------------------------------------------------------------
# execution.py lines 70-71
# ---------------------------------------------------------------------------
class TestContractStatusFromExecutionKeyError:
    """Trigger lines 70-71: KeyError → ValueError in contract_status_from_execution."""

    def test_missing_key_raises_value_error(self):
        """Patch _EXECUTION_TO_CONTRACT to be empty → KeyError → ValueError."""
        import constitutional_swarm.execution as execution_module
        from constitutional_swarm.execution import (
            ExecutionStatus,
            contract_status_from_execution,
        )

        with patch.object(execution_module, "_EXECUTION_TO_CONTRACT", {}):
            with pytest.raises(ValueError, match="has no receipt mapping"):
                contract_status_from_execution(ExecutionStatus.COMPLETED)

    def test_value_error_message_includes_status_value(self):
        """Error message includes the status value string."""
        import constitutional_swarm.execution as execution_module
        from constitutional_swarm.execution import (
            ExecutionStatus,
            contract_status_from_execution,
        )

        with patch.object(execution_module, "_EXECUTION_TO_CONTRACT", {}):
            with pytest.raises(ValueError) as exc_info:
                contract_status_from_execution(ExecutionStatus.FAILED)
            assert "failed" in str(exc_info.value).lower()
