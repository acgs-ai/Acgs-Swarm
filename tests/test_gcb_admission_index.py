"""An optional physical index preserves legacy admission and authority semantics."""

from __future__ import annotations

import json
import sqlite3

import pytest

from constitutional_swarm import governed_commit as module
from constitutional_swarm.apcc import sqlite_store
from constitutional_swarm.governance_errors import GovernanceBypassDenied
from constitutional_swarm.workflow_profile import WorkflowProfile
from tests.test_governed_commit import _configured_boundary, _trusted_admin

INDEX = module._GCB_ADMISSION_INDEX


def snapshot(path):
    with sqlite3.connect(path) as connection:
        schema = connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
        tables = [row[1] for row in schema if row[0] == "table"]
        rows = {
            table: connection.execute(
                f'SELECT * FROM "{table}" ORDER BY rowid'
            ).fetchall()
            for table in tables
        }
        return schema, rows


def test_provision_has_exact_nonunique_index_and_reopens(tmp_path):
    admin, _, _ = _configured_boundary(tmp_path)
    with sqlite3.connect(admin.path) as connection:
        metadata = [
            row[1:]
            for row in connection.execute("PRAGMA index_list(gcb_control_events)")
            if row[1] == INDEX
        ]
        assert metadata == [(INDEX, 0, "c", 0)]
        assert connection.execute(f"PRAGMA index_xinfo({INDEX})").fetchall() == [
            (0, 2, "workflow_id", 0, "BINARY", 1),
            (1, 1, "action", 0, "BINARY", 1),
            (2, 5, "outcome", 0, "BINARY", 1),
            (3, -1, None, 0, "BINARY", 0),
        ]
    before = snapshot(admin.path)
    _trusted_admin(admin.path)
    assert snapshot(admin.path) == before


@pytest.mark.parametrize("legacy", [False, True])
def test_reopen_does_not_migrate_repair_or_change_checkpoint(
    tmp_path, monkeypatch, legacy
):
    admin, _, _ = _configured_boundary(tmp_path)
    if legacy:
        with sqlite3.connect(admin.path) as connection:
            connection.execute(f"DROP INDEX {INDEX}")
    before = snapshot(admin.path)
    trace = []
    original = module.GovernedCommitBoundary._connect

    def connect(self):
        connection = original(self)
        connection.set_trace_callback(trace.append)
        return connection

    monkeypatch.setattr(module.GovernedCommitBoundary, "_connect", connect)
    _trusted_admin(admin.path)
    assert snapshot(admin.path) == before
    assert not any(
        sql.lstrip()
        .upper()
        .startswith(
            ("CREATE ", "ALTER ", "DROP ", "INSERT ", "UPDATE ", "DELETE ", "REPLACE ")
        )
        for sql in trace
    )


@pytest.mark.parametrize(
    "replacement",
    [
        "CREATE INDEX {name} ON gcb_control_events(action,workflow_id,outcome)",
        "CREATE INDEX {name} ON gcb_control_events(workflow_id,action,reason)",
        "CREATE INDEX {name} ON gcb_control_events(workflow_id COLLATE NOCASE,action,outcome)",
        "CREATE INDEX {name} ON gcb_control_events(workflow_id DESC,action,outcome)",
        "CREATE UNIQUE INDEX {name} ON gcb_control_events(workflow_id,action,outcome)",
        "CREATE INDEX {name} ON gcb_control_events(workflow_id,action,outcome) WHERE outcome='committed'",
        "CREATE INDEX {name} ON gcb_control_events(lower(workflow_id),action,outcome)",
        "CREATE INDEX {name} ON gcb_control_events(workflow_id,action,outcome,command_id)",
        "CREATE INDEX {name} ON nodes(workflow_id,node_id)",
        "CREATE INDEX {name} ON metadata(key)",
        "CREATE TABLE {name}(value TEXT)",
    ],
)
def test_reserved_index_malformed_or_global_collision_rejected_without_mutation(
    tmp_path, replacement
):
    admin, _, _ = _configured_boundary(tmp_path)
    with sqlite3.connect(admin.path) as connection:
        connection.execute(f"DROP INDEX {INDEX}")
        connection.execute(replacement.format(name=INDEX))
    before = snapshot(admin.path)
    with pytest.raises(GovernanceBypassDenied, match="authority_schema_shape_mismatch"):
        _trusted_admin(admin.path)
    assert snapshot(admin.path) == before


@pytest.mark.parametrize(
    "change",
    [
        "CREATE INDEX unexpected_control_index ON gcb_control_events(workflow_id)",
        "DROP INDEX idx_outbox_pending",
        "DROP INDEX idx_revocation_pending",
    ],
)
@pytest.mark.parametrize("legacy", [False, True])
def test_extra_or_missing_old_index_still_fails_closed(tmp_path, change, legacy):
    admin, _, _ = _configured_boundary(tmp_path)
    with sqlite3.connect(admin.path) as connection:
        if legacy:
            connection.execute(f"DROP INDEX {INDEX}")
        connection.execute(change)
    before = snapshot(admin.path)
    with pytest.raises(GovernanceBypassDenied, match="authority_schema_shape_mismatch"):
        _trusted_admin(admin.path)
    assert snapshot(admin.path) == before


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize(
    "case", ["valid", "missing", "duplicate", "malformed", "signature", "profile"]
)
def test_admission_results_match_for_indexed_and_legacy_profiles(
    tmp_path, legacy, case
):
    admin, _, _ = _configured_boundary(tmp_path)
    boundary = admin.commit_port
    with sqlite3.connect(admin.path) as connection:
        if legacy:
            connection.execute(f"DROP INDEX {INDEX}")
        if case == "missing":
            connection.execute(
                "DELETE FROM gcb_control_events WHERE action='create_workflow'"
            )
        elif case == "duplicate":
            row = list(
                connection.execute(
                    "SELECT * FROM gcb_control_events WHERE action='create_workflow'"
                ).fetchone()
            )
            row[0] = "duplicate-admission"
            connection.execute(
                "INSERT INTO gcb_control_events VALUES (?,?,?,?,?,?,?,?,?,?)", row
            )
        elif case in {"malformed", "signature"}:
            material = connection.execute(
                "SELECT command_material FROM gcb_control_events WHERE action='create_workflow'"
            ).fetchone()[0]
            if case == "malformed":
                material = "{broken"
            else:
                parsed = json.loads(material)
                parsed["signature"] = "AAAA"
                material = json.dumps(parsed)
            connection.execute(
                "UPDATE gcb_control_events SET command_material=? WHERE action='create_workflow'",
                (material,),
            )
        if case == "profile":
            boundary.workflow_profile = WorkflowProfile.W6_INDEPENDENT_10000
        before = connection.total_changes
        if case == "valid":
            boundary._verify_workflow_profile(connection, "wf")
        else:
            expected = (
                "workflow_profile_mismatch"
                if case == "profile"
                else "workflow_profile_admission_missing"
                if case in {"missing", "duplicate"}
                else "workflow_profile_admission_invalid"
            )
            with pytest.raises(GovernanceBypassDenied, match=expected):
                boundary._verify_workflow_profile(connection, "wf")
        assert connection.total_changes == before


def test_index_deletion_preserves_apcc_fingerprint_and_all_deterministic_facts(
    tmp_path,
):
    admin, _, _ = _configured_boundary(tmp_path)
    before = snapshot(admin.path)
    fingerprint = sqlite_store._SCHEMA_FINGERPRINT
    with sqlite3.connect(admin.path) as connection:
        connection.execute(f"DROP INDEX {INDEX}")
    _trusted_admin(admin.path)
    schema, rows = snapshot(admin.path)
    assert rows == before[1]
    assert schema == [row for row in before[0] if row[1] != INDEX]
    assert sqlite_store._SCHEMA_FINGERPRINT == fingerprint


def test_reserved_index_name_cannot_alias_unrelated_trigger(tmp_path):
    admin, _, _ = _configured_boundary(tmp_path)
    with sqlite3.connect(admin.path) as connection:
        connection.execute(
            f"CREATE TRIGGER {INDEX} AFTER INSERT ON metadata BEGIN SELECT 1; END"
        )
    before = snapshot(admin.path)
    with sqlite3.connect(admin.path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name=?", (INDEX,)
            ).fetchone()[0]
            == 2
        )
        with pytest.raises(
            GovernanceBypassDenied, match="authority_schema_shape_mismatch"
        ):
            module.GovernedCommitBoundary._validate_schema_shape(connection)
    assert snapshot(admin.path) == before


@pytest.mark.parametrize("legacy", [False, True])
def test_public_workflow_attach_preserves_success_and_policy_denial(tmp_path, legacy):
    admin, _, _ = _configured_boundary(tmp_path)
    if legacy:
        with sqlite3.connect(admin.path) as connection:
            connection.execute(f"DROP INDEX {INDEX}")
    before = snapshot(admin.path)
    result = admin.commit_port.attach_workflow(
        workflow_id="wf", nodes={"root": (), "child": ("root",)}, policy_version="1"
    )
    assert set(result) == {"root", "child"}
    with pytest.raises(GovernanceBypassDenied, match="recovery_policy_mismatch"):
        admin.commit_port.attach_workflow(
            workflow_id="wf", nodes={"root": (), "child": ("root",)}, policy_version="2"
        )
    assert snapshot(admin.path) == before
