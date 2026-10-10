"""C47 regression tests: benchmark tooling hardening.

Covers bench-eval-14 (strict JSON in the benchmark CLI), bench-eval-12 /
bench-eval-opt-8 (TLC jar copy-then-hash, shared pin, java resolved once),
bench-eval-opt-7 (reviewer-blind checkbox), and the dead-code removals
bench-eval-opt-3 / bench-eval-opt-4.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest

import constitutional_swarm.forensic_benchmark as forensic_benchmark
import scripts.run_tlc_expected_witness as witness
from scripts import run_governance_benchmark as benchmark_cli

ROOT = Path(__file__).resolve().parents[1]
PINNED_TLC_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"


def _load_script(name: str) -> ModuleType:
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"c47_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# bench-eval-14: security-relevant JSON in the CLI must reject duplicate keys
# ---------------------------------------------------------------------------


def test_answer_seal_with_duplicate_keys_is_rejected(tmp_path: Path) -> None:
    seal_path = tmp_path / "answer_seal.json"
    seal_path.write_text(
        '{"schema": "decoy", "schema": "acgs-v0.1-collected-blind-answers-seal"}'
    )
    verdict = benchmark_cli._verify_collected_blind_answers_seal(
        seal_path,
        tmp_path / "answers.csv",
        tmp_path / "packet",
        None,
        protocol_path=tmp_path / "protocol.json",
        answer_key_path=tmp_path / "answer_key.json",
        condition_key_path=tmp_path / "condition_key.json",
    )
    assert verdict["valid"] is False
    issues = cast(list[dict[str, str]], verdict["issues"])
    assert issues[0]["code"] == "invalid_answer_seal"
    assert "duplicate" in issues[0]["message"]


def test_reviewer_manifest_with_duplicate_keys_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "reviewer_manifest.json").write_text(
        '{"files": {}, "file_count": 0, "files": {}}'
    )
    verdict = benchmark_cli._verify_reviewer_manifest(tmp_path)
    assert verdict["valid"] is False
    issues = cast(list[dict[str, str]], verdict["issues"])
    assert issues[0]["code"] == "invalid_reviewer_manifest"
    assert "duplicate" in issues[0]["message"]


def test_kit_manifest_with_duplicate_keys_is_structured_failure(tmp_path: Path) -> None:
    (tmp_path / "kit_manifest.json").write_text('{"files": {}, "files": {}}')
    verdict = benchmark_cli._verify_replication_kit(tmp_path)
    assert verdict["valid"] is False
    assert verdict["checked_files"] == 0
    issues = cast(list[dict[str, str]], verdict["issues"])
    assert [issue["code"] for issue in issues] == ["invalid_kit_manifest"]
    assert "duplicate" in issues[0]["message"]


def test_malformed_kit_manifest_is_structured_failure_not_traceback(
    tmp_path: Path,
) -> None:
    (tmp_path / "kit_manifest.json").write_text("{not json")
    verdict = benchmark_cli._verify_replication_kit(tmp_path)
    assert verdict["valid"] is False
    issues = cast(list[dict[str, str]], verdict["issues"])
    assert issues[0]["code"] == "invalid_kit_manifest"


def test_packet_inventory_treats_duplicate_key_manifest_as_listing_nothing(
    tmp_path: Path,
) -> None:
    (tmp_path / "reviewer_manifest.json").write_text(
        '{"files": {}, "files": {"smuggled.json": {}}}'
    )
    (tmp_path / "smuggled.json").write_text("{}")
    issues = benchmark_cli._reviewer_packet_inventory_issues(tmp_path)
    assert any("smuggled.json" in issue["message"] for issue in issues)


def _privacy_codes(packet_dir: Path) -> dict[str, str]:
    verdict = benchmark_cli._audit_reviewer_packet(packet_dir)
    privacy = cast(dict[str, Any], verdict["privacy"])
    return {issue["code"]: issue["message"] for issue in privacy["issues"]}


def test_packet_audit_flags_duplicate_key_coordinator_manifest(tmp_path: Path) -> None:
    (tmp_path / "notes.json").write_text(
        '{"files": {"coordinator_pack/condition_key.json": {}}, "files": {}}'
    )
    verdict = benchmark_cli._audit_reviewer_packet(tmp_path)
    assert verdict["valid"] is False
    codes = _privacy_codes(tmp_path)
    assert "ambiguous_packet_json" in codes
    assert "notes.json" in codes["ambiguous_packet_json"]


@pytest.mark.parametrize(
    "content",
    [
        '{"value": NaN}',
        "[" * 100_000 + "]" * 100_000,
    ],
)
def test_packet_audit_flags_non_strict_json_documents(
    tmp_path: Path, content: str
) -> None:
    (tmp_path / "doc.json").write_text(content)
    assert "ambiguous_packet_json" in _privacy_codes(tmp_path)


def test_packet_audit_does_not_flag_non_json_text(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("incident_id,answer\nincident-001,yes\n")
    assert "ambiguous_packet_json" not in _privacy_codes(tmp_path)


def test_answer_key_with_duplicate_keys_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "answer_key.json"
    path.write_text('{"incident-001": {"q": "a"}, "incident-001": {"q": "b"}}')
    with pytest.raises(ValueError, match="duplicate"):
        benchmark_cli._load_answer_key(path)


def test_condition_key_with_duplicate_keys_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "condition_key.json"
    path.write_text(
        '{"conditions": {}, "pack_nonce": "' + "0" * 64 + '", "conditions": {}}'
    )
    with pytest.raises(ValueError, match="duplicate"):
        benchmark_cli._load_condition_key_envelope(path)


def test_public_artifacts_inventory_with_duplicate_keys_is_unreadable(
    tmp_path: Path,
) -> None:
    path = tmp_path / "required_public_artifacts.json"
    path.write_text('{"schema": "x", "schema": "acgs-v0.1-required-public-artifacts"}')
    verdict = benchmark_cli._validate_required_public_artifacts_inventory(path)
    assert verdict["valid"] is False
    issues = cast(list[dict[str, str]], verdict["issues"])
    assert issues[0]["code"] == "required_public_artifacts_unreadable"
    assert "duplicate" in issues[0]["message"]


def test_cli_has_no_lenient_json_at_security_sites() -> None:
    source = (ROOT / "scripts" / "run_governance_benchmark.py").read_text()
    for needle in (
        "json.loads(seal_path.read_text())",
        "json.loads(manifest_path.read_text())",
        'json.loads(canonical_files["reviewer_manifest.json"])',
        "json.loads(submission_json_path.read_text())",
        "json.loads(path.read_text())",
    ):
        assert needle not in source
    # Only the repo-owned request template and the ambiguity probe stay lenient.
    lenient = [line.strip() for line in source.splitlines() if "json.loads(" in line]
    assert lenient == ["return json.loads(request_path.read_text())", "json.loads(text)"]


# ---------------------------------------------------------------------------
# bench-eval-12 / bench-eval-opt-8: pinned TLC jar is copied, hashed, executed
# ---------------------------------------------------------------------------


def test_tlc_pin_lives_in_one_shared_module() -> None:
    common = _load_script("_tlc_common")
    apcc = _load_script("run_apcc_tlc")
    assert common.TLC_JAR_SHA256 == PINNED_TLC_SHA256
    assert apcc.TLC_JAR_SHA256 == PINNED_TLC_SHA256
    assert witness.TLC_JAR_SHA256 == PINNED_TLC_SHA256
    for name in ("run_apcc_tlc.py", "run_tlc_expected_witness.py"):
        source = (ROOT / "scripts" / name).read_text()
        assert PINNED_TLC_SHA256 not in source
        assert "def _sha256" not in source


def _valid_witness_output() -> str:
    from tests.test_tlc_expected_witness import _valid_output

    return _valid_output()


def test_witness_runner_executes_the_hashed_private_copy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    jar = tmp_path / "tla2tools.jar"
    jar.write_bytes(b"pinned-fixture")
    hashed: list[Path] = []
    observed: dict[str, Any] = {}

    def fake_sha256(path: Path) -> str:
        hashed.append(Path(path))
        # Attacker swaps the user-supplied jar after the digest check.
        jar.write_bytes(b"swapped-malicious-jar")
        return PINNED_TLC_SHA256

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        classpath = Path(argv[argv.index("-cp") + 1])
        observed.update(
            argv=argv,
            cwd=Path(kwargs["cwd"]),
            classpath=classpath,
            executed_bytes=classpath.read_bytes(),
        )
        return subprocess.CompletedProcess(argv, 12, _valid_witness_output(), "")

    monkeypatch.setattr(witness, "_sha256", fake_sha256)
    monkeypatch.setattr(witness.subprocess, "run", fake_run)
    result = witness.run_tlc_expected_witness(tlc_jar=jar, log_path=tmp_path / "w.log")

    assert result.outcome is witness.Outcome.EXPECTED_WITNESS
    classpath = observed["classpath"]
    assert classpath != jar.resolve()
    assert classpath.is_relative_to(observed["cwd"])
    assert hashed == [classpath]
    assert observed["executed_bytes"] == b"pinned-fixture"
    assert not observed["cwd"].exists()


def test_witness_runner_resolves_java_to_an_absolute_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    jar = tmp_path / "tla2tools.jar"
    jar.write_bytes(b"pinned-fixture")
    calls: list[str] = []
    observed: dict[str, Any] = {}

    def fake_which(command: str) -> str:
        calls.append(command)
        return "/opt/pinned-jdk/bin/java"

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["argv"] = argv
        return subprocess.CompletedProcess(argv, 12, _valid_witness_output(), "")

    monkeypatch.setattr(witness, "_sha256", lambda _path: PINNED_TLC_SHA256)
    monkeypatch.setattr("shutil.which", fake_which)
    monkeypatch.setattr(witness.subprocess, "run", fake_run)
    witness.run_tlc_expected_witness(tlc_jar=jar, log_path=tmp_path / "w.log")

    assert calls == ["java"]
    assert observed["argv"][0] == "/opt/pinned-jdk/bin/java"


def test_witness_runner_rejects_copy_that_does_not_match_pin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    jar = tmp_path / "tla2tools.jar"
    jar.write_bytes(b"not-the-pinned-jar")

    def unexpected_run(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("TLC must not run with an unpinned jar")

    monkeypatch.setattr(witness.subprocess, "run", unexpected_run)
    result = witness.run_tlc_expected_witness(tlc_jar=jar, log_path=tmp_path / "w.log")
    assert result.outcome is witness.Outcome.TLC_RUNTIME_ERROR
    assert "pinned" in result.detail


def test_apcc_runner_hashes_once_and_runs_private_copy_for_every_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    apcc = _load_script("run_apcc_tlc")
    jar = tmp_path / "tla2tools.jar"
    jar.write_bytes(b"pinned-fixture")
    hashed: list[Path] = []
    which_calls: list[str] = []
    runs: list[tuple[list[str], bytes]] = []

    def fake_sha256(path: Path) -> str:
        hashed.append(Path(path))
        jar.write_bytes(b"swapped-malicious-jar")
        return PINNED_TLC_SHA256

    def fake_which(command: str) -> str:
        which_calls.append(command)
        return "/opt/pinned-jdk/bin/java"

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        classpath = Path(argv[argv.index("-cp") + 1])
        runs.append((argv, classpath.read_bytes()))
        output = f"{apcc.TLC_VERSION_LINE}\nModel checking completed. No error has been found.\n"
        return subprocess.CompletedProcess(argv, 0, output, "")

    monkeypatch.setattr(apcc, "_sha256", fake_sha256)
    monkeypatch.setattr("shutil.which", fake_which)
    monkeypatch.setattr(apcc.subprocess, "run", fake_run)
    exit_code = apcc.main(
        [
            "--tlc-jar",
            str(jar),
            "--specs",
            str(tmp_path),
            "--config",
            "apcc_safety.cfg",
            "--config",
            "apcc_liveness.cfg",
        ]
    )

    assert exit_code == 0
    assert which_calls == ["java"]
    assert len(hashed) == 1 and hashed[0] != jar
    assert len(runs) == 2
    for argv, executed in runs:
        assert argv[0] == "/opt/pinned-jdk/bin/java"
        assert Path(argv[argv.index("-cp") + 1]) == hashed[0]
        assert executed == b"pinned-fixture"
    assert not hashed[0].exists()


def test_apcc_runner_rejects_unpinned_jar_without_running_tlc(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    apcc = _load_script("run_apcc_tlc")
    jar = tmp_path / "tla2tools.jar"
    jar.write_bytes(b"not-the-pinned-jar")

    def unexpected_run(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("TLC must not run with an unpinned jar")

    monkeypatch.setattr(apcc.subprocess, "run", unexpected_run)
    assert apcc.main(["--tlc-jar", str(jar), "--config", "apcc_safety.cfg"]) == 2
    assert apcc.main(["--tlc-jar", str(tmp_path / "missing.jar")]) == 2


# ---------------------------------------------------------------------------
# bench-eval-opt-7: the reviewer-blind checkbox never overclaims blinding
# ---------------------------------------------------------------------------


def _render(reviewer_count: object) -> str:
    replication = SimpleNamespace(
        replicating_group="Independent Lab",
        reproduction_notes="notes",
        scorecard_uri="https://example.invalid/scorecard",
        reviewer_cohort_uri="https://example.invalid/cohort",
        attestation_uri="https://example.invalid/attestation",
        artifact_pack_uri="https://example.invalid/pack",
        completed=False,
    )
    return cast(
        str,
        benchmark_cli._render_external_replication_submission_markdown(
            public_request={
                "release_url": "https://example.invalid/release",
                "issue_url": "https://example.invalid/issue",
                "verification_commands": [],
            },
            bundle_summary={"reviewer_count": reviewer_count},
            replication_metadata=cast(Any, replication),
            result_bundle_url="https://example.invalid/bundle",
            replication_metadata_url="https://example.invalid/meta",
            commands_transcript_url="https://example.invalid/transcript",
        ),
    )


def _reviewer_blind_box(markdown: str) -> str:
    match = re.search(r"- \[(.)\] The reviewers only saw blinded artifacts", markdown)
    assert match is not None
    return match.group(1)


@pytest.mark.parametrize("reviewer_count", [0, 2, 5, 6, 9, 600, True, "6", None, 6.0])
def test_reviewer_blind_checkbox_is_never_pre_ticked(reviewer_count: object) -> None:
    markdown = _render(reviewer_count)
    assert _reviewer_blind_box(markdown) == " "
    assert "reviewer blinding is not authenticated" in markdown


def test_reviewer_count_is_displayed_only_when_an_exact_int() -> None:
    assert "reviewer_count=6;" in _render(6)
    assert "(reviewer_count=6)" in _render(6)
    for invalid in (True, "6", 6.0, None):
        markdown = _render(invalid)
        assert "reviewer_count=unknown;" in markdown
        assert "(reviewer_count=unknown)" in markdown


def test_renderer_no_longer_accepts_unused_trusted_attestors() -> None:
    with pytest.raises(TypeError):
        benchmark_cli._render_external_replication_submission_markdown(  # type: ignore[call-arg]
            public_request={},
            bundle_summary={},
            replication_metadata=cast(Any, SimpleNamespace()),
            result_bundle_url="",
            replication_metadata_url="",
            commands_transcript_url="",
            trusted_attestors=(),
        )


# ---------------------------------------------------------------------------
# bench-eval-opt-3 / bench-eval-opt-4: dead code removed, audit repointed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "_paired_incident_correctness_contrasts",
        "generate_incident_specs",
        "_incident_spec_from_source",
        "_failure_description",
        "IncidentSpec",
    ],
)
def test_dead_forensic_benchmark_symbols_are_removed(name: str) -> None:
    assert not hasattr(forensic_benchmark, name)


def test_completion_audit_artifacts_resolve_to_real_symbols() -> None:
    source = (ROOT / "scripts" / "run_governance_benchmark.py").read_text()
    references = re.findall(
        r'"src/constitutional_swarm/forensic_benchmark\.py:([A-Za-z_][A-Za-z0-9_]*)"',
        source,
    )
    assert "generate_artifact_pack" in references
    for name in references:
        assert hasattr(forensic_benchmark, name), name
    audit_doc = (ROOT / "docs" / "internal" / "acgs_v0_1_completion_audit.md").read_text()
    assert "generate_incident_specs" not in audit_doc
    assert "generate_artifact_pack" in audit_doc
