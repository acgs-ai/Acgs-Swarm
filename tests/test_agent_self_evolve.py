from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts import agent_self_evolve


ROOT = Path(__file__).resolve().parent.parent


def test_discovers_operational_manifests_and_template_agents() -> None:
    agents = agent_self_evolve.discover_agents(ROOT, include_templates=True)
    names = {agent.name for agent in agents}

    assert "coder" in names
    assert "engineering-code-reviewer" in names
    assert len(agents) >= 100


def test_builds_self_evolve_harness_for_every_discovered_agent() -> None:
    agents = agent_self_evolve.discover_agents(ROOT, include_templates=True)
    report = agent_self_evolve.build_report(ROOT, include_templates=True)

    assert report["summary"]["agents"] == len(agents)
    assert report["summary"]["agents_without_harness"] == 0
    assert set(report["agents"]) == {agent.name for agent in agents}

    for agent_name, payload in report["agents"].items():
        harness = payload["harness"]
        assert harness["agent"] == agent_name
        assert harness["mutation_scope"]
        assert harness["guardrails"]
        assert harness["probes"]
        assert all(probe["id"] and probe["metric"] for probe in harness["probes"])


def test_evaluates_without_live_agent_runtime() -> None:
    report = agent_self_evolve.build_report(ROOT, include_templates=False)

    assert report["summary"]["agents"] == len(list(ROOT.glob("agents/*.agent.yaml")))
    assert report["summary"]["probes_total"] > 0
    assert 0.0 <= report["summary"]["probe_pass_rate"] <= 1.0
    assert "coder" in report["agents"]
    assert report["agents"]["coder"]["harness"]["runtime"] == "offline-static"


def test_cli_help_does_not_require_external_agent_cli() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/agent_self_evolve.py", "--help"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "self-evolution harness" in result.stdout


def test_each_harness_references_hermes_and_smolagents_patterns() -> None:
    report = agent_self_evolve.build_report(ROOT, include_templates=True)

    for payload in report["agents"].values():
        refs = payload["harness"]["reference_patterns"]
        ref_ids = {ref["id"] for ref in refs}
        assert "hermes-runtime-governance" in ref_ids
        assert "smolagents-code-governance" in ref_ids
        assert any("pre_tool" in seam for ref in refs for seam in ref["seams"])
        assert any("executor" in seam for ref in refs for seam in ref["seams"])


def test_reference_patterns_are_source_backed() -> None:
    report = agent_self_evolve.build_report(ROOT, include_templates=False)
    refs = report["reference_patterns"]

    assert refs["hermes-runtime-governance"]["source"].endswith("hermes_acgs_middleware.py")
    assert refs["smolagents-code-governance"]["source"].startswith("https://huggingface.co/docs/smolagents/")
    assert "fail-closed" in " ".join(refs["hermes-runtime-governance"]["principles"])
    assert "generated code" in " ".join(refs["smolagents-code-governance"]["principles"])


def test_harness_is_available_as_package_module() -> None:
    from constitutional_swarm import agent_self_evolve as packaged

    report = packaged.build_report(ROOT, include_templates=False)

    assert report["summary"]["operational_agents"] == len(list(ROOT.glob("agents/*.agent.yaml")))
    assert "coder" in report["agents"]


def test_write_report_creates_parent_directories(tmp_path: Path) -> None:
    nested_path = tmp_path / "missing" / "state" / "report.json"
    assert not nested_path.parent.exists()

    rc = agent_self_evolve.main(
        ["--root", str(ROOT), "--no-templates", "--write-report", str(nested_path)]
    )

    assert rc == 0
    assert nested_path.exists()
    payload = json.loads(nested_path.read_text(encoding="utf-8"))
    assert "summary" in payload


def test_pyproject_exposes_agent_self_evolve_console_script() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'acgs-agent-self-evolve = "constitutional_swarm.agent_self_evolve:main"' in text
