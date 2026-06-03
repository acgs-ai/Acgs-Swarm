from __future__ import annotations

import json
from pathlib import Path

import pytest
from constitutional_swarm.governed_handoff import (
    PolicyEngine,
    main,
    read_audit,
    run_task,
    verify_bundle,
)


def write_configs(root: Path) -> None:
    acgs = root / ".acgs"
    acgs.mkdir()
    (acgs / "constitution.yaml").write_text(
        r"""
schema_version: 1
policy:
  unknown_decisions: fail_closed
  protected_paths:
    - ".acgs/**"
    - "protected/**"
  secret_command_patterns:
    - '\b(cat|grep|rg)\b.*(\.env|secret|token)'
    - '\b(printenv|env)\b'
""",
        encoding="utf-8",
    )
    (acgs / "swarm.yaml").write_text(
        """
schema_version: 1
roles:
  proposer: {adapter: mock}
  executor: {adapter: mock}
  validator: {adapter: mock}
  observer: {adapter: mock}
adapters:
  mock: {}
""",
        encoding="utf-8",
    )


def test_task_cannot_execute_before_intake_policy_passes(tmp_path: Path) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text("", encoding="utf-8")

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "blocked"
    assert not (tmp_path / "output.txt").exists()
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert bundle["policy_decisions"][0]["gate"] == "intake"
    assert bundle["policy_decisions"][0]["outcome"] == "deny"


def test_unknown_policy_gate_fails_closed(tmp_path: Path) -> None:
    write_configs(tmp_path)
    engine = PolicyEngine(
        {"policy": {}},
        {"roles": {"executor": {}, "observer": {}, "proposer": {}, "validator": {}}},
        tmp_path,
    )

    decision = engine.decide("not_a_gate", "anything")

    assert decision.outcome == "deny"
    assert "fail closed" in decision.reason


def test_missing_role_assignments_fail_closed_at_intake(tmp_path: Path) -> None:
    write_configs(tmp_path)
    (tmp_path / ".acgs" / "swarm.yaml").write_text(
        "schema_version: 1\nroles:\n  executor: {adapter: mock}\n",
        encoding="utf-8",
    )
    task = tmp_path / "task.md"
    task.write_text(
        "task_id: missing-roles\nACGS_WRITE output.txt :: no", encoding="utf-8"
    )

    result = run_task(task, repo_root=tmp_path)

    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert result.final_state == "blocked"
    assert bundle["policy_decisions"][0]["gate"] == "intake"
    assert bundle["policy_decisions"][0]["outcome"] == "deny"
    assert "missing role assignments" in bundle["policy_decisions"][0]["reason"]


def test_protected_path_edit_requires_human_review_after_test_proof(
    tmp_path: Path,
) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text(
        "\n".join(
            [
                "task_id: protected-review",
                "ACGS_WRITE protected/config.txt :: changed",
                'ACGS_TEST python -c "print(1)"',
            ]
        ),
        encoding="utf-8",
    )

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "human_review_required"
    assert not (tmp_path / "protected/config.txt").exists()
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert any(
        decision["gate"] == "file_write"
        and decision["outcome"] == "human_review_required"
        for decision in bundle["policy_decisions"]
    )
    assert bundle["tests_run"][0]["passed"] is True


def test_secret_reading_command_is_denied(tmp_path: Path) -> None:
    write_configs(tmp_path)
    (tmp_path / ".env").write_text("DUMMY_VALUE=[REDACTED]\n", encoding="utf-8")
    task = tmp_path / "task.md"
    task.write_text(
        "\n".join(
            [
                "task_id: secret-denied",
                "ACGS_TOOL cat .env",
                'ACGS_TEST python -c "print(1)"',
            ]
        ),
        encoding="utf-8",
    )

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "blocked"
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert any(
        decision["gate"] == "tool_call" and decision["outcome"] == "deny"
        for decision in bundle["policy_decisions"]
    )


def test_write_directive_cannot_escape_repo_root(tmp_path: Path) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text(
        "\n".join(
            [
                "task_id: outside-write-denied",
                "ACGS_WRITE ../outside.txt :: bad",
                'ACGS_TEST python -c "print(1)"',
            ]
        ),
        encoding="utf-8",
    )

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "blocked"
    assert not (tmp_path.parent / "outside.txt").exists()
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert any(
        decision["gate"] == "file_write"
        and decision["outcome"] == "deny"
        and "escapes repository root" in decision["reason"]
        for decision in bundle["policy_decisions"]
    )
    assert bundle["file_changes"] == []


def test_test_proof_required_before_handoff(tmp_path: Path) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text(
        "task_id: no-test\nACGS_WRITE output.txt :: changed", encoding="utf-8"
    )

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "blocked"
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert any(
        decision["gate"] == "handoff"
        and decision["outcome"] == "deny"
        and "test proof" in decision["reason"]
        for decision in bundle["policy_decisions"]
    )


def test_one_passing_test_proof_allows_handoff(tmp_path: Path) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text(
        "\n".join(
            [
                "task_id: happy-path",
                "ACGS_WRITE output/result.txt :: changed",
                'ACGS_TEST python -c "print(1)"',
            ]
        ),
        encoding="utf-8",
    )

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "handoff_ready"
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    for key in [
        "constitution_hash",
        "workflow_hash",
        "task_metadata",
        "role_assignments",
        "policy_decisions",
        "tool_events",
        "file_changes",
        "tests_run",
        "final_state",
        "chain_hash",
    ]:
        assert key in bundle
    assert verify_bundle(result.bundle_path)["ok"] is True
    assert read_audit(result.audit_path)[-1]["event_hash"] == bundle["chain_hash"]


def test_bundle_verification_detects_broken_hash_chain(tmp_path: Path) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text(
        'task_id: tamper-check\nACGS_WRITE output.txt :: ok\nACGS_TEST python -c "print(1)"',
        encoding="utf-8",
    )
    result = run_task(task, repo_root=tmp_path)
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    bundle["audit_path"] = str(tmp_path / "missing.audit.jsonl")
    bundle["audit_events"][1]["payload"]["task_hash"] = "tampered"
    tampered_bundle = tmp_path / "tampered.bundle.json"
    tampered_bundle.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")

    verification = verify_bundle(tampered_bundle)

    assert verification["ok"] is False
    assert "event_hash mismatch" in verification["error"]


def test_cli_run_verify_and_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text(
        'task_id: cli-task\nACGS_WRITE output.txt :: ok\nACGS_TEST python -c "print(1)"',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["run", "--task", str(task)]) == 0
    assert main(["verify", "--bundle", ".acgs/evidence/cli-task.bundle.json"]) == 0
    assert main(["pack", "--task", "cli-task"]) == 0


# --- Hardening: forgery-resistant signed bundle + allowlist + version pin ------


def _keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()


def _happy_task(tmp_path: Path, task_id: str) -> Path:
    task = tmp_path / "task.md"
    task.write_text(
        "\n".join(
            [
                f"task_id: {task_id}",
                "ACGS_WRITE output/result.txt :: changed",
                'ACGS_TEST python -c "print(1)"',
            ]
        ),
        encoding="utf-8",
    )
    return task


def test_signed_bundle_verifies_with_trusted_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_configs(tmp_path)
    seed_hex, pub_hex = _keypair()
    monkeypatch.setenv("ACGS_SIGNING_KEY", seed_hex)

    result = run_task(_happy_task(tmp_path, "signed-ok"), repo_root=tmp_path)

    assert result.final_state == "handoff_ready"
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert bundle["signature"]["alg"] == "ed25519"
    verdict = verify_bundle(
        result.bundle_path, trusted_public_keys={"acgs-supervisor": pub_hex}
    )
    assert verdict["ok"] is True
    assert verdict["signature_status"] == "valid"


def test_unsigned_self_consistent_chain_rejected_under_trust_anchor(
    tmp_path: Path,
) -> None:
    # The exact hole the old code missed: a fully self-consistent chain with no
    # valid signature must FAIL once authorship (a trust anchor) is required.
    write_configs(tmp_path)
    result = run_task(_happy_task(tmp_path, "unsigned"), repo_root=tmp_path)
    assert result.final_state == "handoff_ready"

    # Backward-compatible: chain-only verification (no anchor) still passes.
    assert verify_bundle(result.bundle_path)["ok"] is True

    _, pub_hex = _keypair()
    verdict = verify_bundle(
        result.bundle_path, trusted_public_keys={"acgs-supervisor": pub_hex}
    )
    assert verdict["chain_ok"] is True
    assert verdict["signature_status"] == "unsigned"
    assert verdict["ok"] is False


def test_signed_bundle_with_wrong_key_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_configs(tmp_path)
    seed_hex, _ = _keypair()
    _, other_pub = _keypair()
    monkeypatch.setenv("ACGS_SIGNING_KEY", seed_hex)

    result = run_task(_happy_task(tmp_path, "wrong-key"), repo_root=tmp_path)

    verdict = verify_bundle(
        result.bundle_path, trusted_public_keys={"acgs-supervisor": other_pub}
    )
    assert verdict["signature_status"] == "invalid"
    assert verdict["ok"] is False


def test_tampered_signed_summary_breaks_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_configs(tmp_path)
    seed_hex, pub_hex = _keypair()
    monkeypatch.setenv("ACGS_SIGNING_KEY", seed_hex)
    result = run_task(_happy_task(tmp_path, "tamper-sig"), repo_root=tmp_path)
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))

    # Mutate a SIGNED summary field the chain check does not re-derive: chain stays
    # consistent, but the signature must no longer verify.
    bundle["constitution_hash"] = "tampered"
    result.bundle_path.write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    verdict = verify_bundle(
        result.bundle_path, trusted_public_keys={"acgs-supervisor": pub_hex}
    )
    assert verdict["chain_ok"] is True
    assert verdict["signature_status"] == "invalid"
    assert verdict["ok"] is False


def test_allowlist_denies_non_whitelisted_command(tmp_path: Path) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text(
        "\n".join(
            [
                "task_id: allowlist-deny",
                "ACGS_TOOL curl http://example.com/x",
                'ACGS_TEST python -c "print(1)"',
            ]
        ),
        encoding="utf-8",
    )

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "blocked"
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert any(
        decision["gate"] == "tool_call"
        and decision["outcome"] == "deny"
        and "allowlist" in decision["reason"]
        for decision in bundle["policy_decisions"]
    )


def test_constitution_version_mismatch_fails_closed_at_intake(tmp_path: Path) -> None:
    write_configs(tmp_path)
    (tmp_path / ".acgs" / "constitution.yaml").write_text(
        "schema_version: 1\n"
        "constitutional_version: deadbeefdeadbeef\n"
        "policy:\n"
        '  protected_paths:\n    - ".acgs/**"\n',
        encoding="utf-8",
    )

    result = run_task(_happy_task(tmp_path, "ver-mismatch"), repo_root=tmp_path)

    assert result.final_state == "blocked"
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert any(
        decision["gate"] == "intake"
        and decision["outcome"] == "deny"
        and "does not match pinned" in decision["reason"]
        for decision in bundle["policy_decisions"]
    )


def test_constitution_matching_version_pin_is_allowed(tmp_path: Path) -> None:
    from constitutional_swarm.constants import CONSTITUTIONAL_HASH

    write_configs(tmp_path)
    (tmp_path / ".acgs" / "constitution.yaml").write_text(
        "schema_version: 1\n"
        f"constitutional_version: {CONSTITUTIONAL_HASH}\n"
        "policy:\n"
        '  protected_paths:\n    - ".acgs/**"\n',
        encoding="utf-8",
    )

    result = run_task(_happy_task(tmp_path, "ver-ok"), repo_root=tmp_path)

    assert result.final_state == "handoff_ready"
