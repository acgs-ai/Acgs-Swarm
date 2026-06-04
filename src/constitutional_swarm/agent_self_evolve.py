#!/usr/bin/env python3
"""Build deterministic self-evolution harnesses for repo agents.

The harness is intentionally offline-static: it does not call live LLMs or an
agent runtime. It discovers every operational role manifest and, optionally, the
vendored persona templates, then emits a per-agent probe plan plus static gate
results. Live optimizers can consume this JSON as the safe first pass before
running costly or mutating agent experiments.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


OPERATIONAL_AGENT_GLOB = "agents/*.agent.yaml"
TEMPLATE_AGENT_GLOB = "agents/templates/**/*.md"
REQUIRED_MANIFEST_KEYS = {
    "name",
    "purpose",
    "scope",
    "required_tools",
    "io_contract",
    "safety",
    "execution",
    "validation",
    "artifacts",
}


@dataclass(frozen=True)
class AgentRecord:
    """An agent source that can receive a self-evolution harness."""

    name: str
    kind: str
    path: Path
    data: dict[str, Any]


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        return {}
    return data


def _loose_frontmatter(block: str, error: Exception) -> dict[str, Any]:
    """Best-effort parser for persona files with non-strict YAML metadata.

    Some vendored templates contain display text such as ``Default perspective:``
    without quoting the whole scalar. Discovery must still include those agents so
    the harness can report the parseability defect instead of silently skipping
    the agent.
    """

    data: dict[str, Any] = {"_frontmatter_error": str(error)}
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in {"name", "description", "color", "emoji", "vibe"}:
            data[key] = value.strip().strip('"').strip("'")
    return data


def _frontmatter(path: Path) -> tuple[dict[str, Any], str] | None:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return None
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None
    try:
        data = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError as exc:
        data = _loose_frontmatter(parts[1], exc)
    if not isinstance(data, dict):
        return None
    body = parts[2].strip()
    return data, body



def reference_patterns() -> dict[str, dict[str, Any]]:
    """Source-backed design patterns every self-evolution harness must preserve."""

    return {
        "hermes-runtime-governance": {
            "id": "hermes-runtime-governance",
            # External design references (not vendored here); named by basename so
            # the report stays portable and leaks no local filesystem layout.
            "source": "hermes_acgs_middleware.py",
            "supporting_adr": "adr-0001-in-context-procedure-execution-external-runtime-governance.md",
            "seams": ["pre_tool", "post_tool", "final_check", "evidence_writer"],
            "principles": [
                "runtime gates are authoritative; prompt-level self-attestation is not enough",
                "fail-closed on policy evaluation or audit persistence errors",
                "record decisions as tamper-evident, hash-linked evidence",
                "separate proposer, validator, executor, and observer responsibilities",
            ],
            "harness_implications": [
                "mutations must keep side-effect probes before execution probes",
                "denied or human-required actions must not be counted as successful execution",
                "reports must include evidence/audit completeness, not only task success",
            ],
        },
        "smolagents-code-governance": {
            "id": "smolagents-code-governance",
            "source": "https://huggingface.co/docs/smolagents/en/reference/agents",
            "supporting_local_note": "smolagents-adaptation.md",
            "seams": ["executor", "final_answer_checks", "step_callbacks", "managed_agents"],
            "principles": [
                "govern generated code before execution, because CodeAgent actions are Python code",
                "support both CodeAgent-style code actions and ToolCallingAgent JSON tool calls",
                "use final-answer checks and step callbacks as validation and audit seams",
                "treat the API as experimental and keep adapters duck-typed/version-tolerant",
            ],
            "harness_implications": [
                "include code-action/static-safety probes even for persona-only agents",
                "capture step-level observations and final-answer validation separately",
                "avoid importing optional agent SDKs at module load",
            ],
        },
    }

def _tool_names(root: Path) -> set[str]:
    registry = root / "tools" / "registry.yaml"
    if not registry.exists():
        return set()
    data = _load_yaml(registry)
    tools = data.get("tools", [])
    if not isinstance(tools, list):
        return set()
    return {str(tool.get("name")) for tool in tools if isinstance(tool, dict) and tool.get("name")}


def discover_agents(root: Path | str = ".", *, include_templates: bool = True) -> list[AgentRecord]:
    """Discover every repo agent source that should have a harness.

    Operational agents are the machine-readable ``agents/*.agent.yaml`` files.
    Template agents are Markdown files under ``agents/templates`` that have YAML
    frontmatter with both ``name`` and ``description``; docs such as README and
    INVENTORY are ignored.
    """

    root_path = Path(root)
    records: list[AgentRecord] = []

    for path in sorted(root_path.glob(OPERATIONAL_AGENT_GLOB)):
        data = _load_yaml(path)
        name = str(data.get("name") or path.name[: -len(".agent.yaml")])
        records.append(AgentRecord(name=name, kind="operational", path=path, data=data))

    if include_templates:
        for path in sorted(root_path.glob(TEMPLATE_AGENT_GLOB)):
            fm = _frontmatter(path)
            if fm is None:
                continue
            data, body = fm
            if not data.get("name") or not data.get("description"):
                continue
            payload = dict(data)
            payload["body"] = body
            payload["display_name"] = data.get("name")
            # Use the filename stem as the stable machine id. Template
            # frontmatter often contains display names with spaces/title case.
            records.append(
                AgentRecord(name=path.stem, kind="template", path=path, data=payload)
            )

    return records


def _check(check_id: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"id": check_id, "passed": bool(passed), "detail": detail}


def _manifest_checks(agent: AgentRecord, tool_names: set[str]) -> list[dict[str, Any]]:
    data = agent.data
    missing_keys = sorted(REQUIRED_MANIFEST_KEYS.difference(data))
    required_tools_raw = data.get("required_tools")
    required_tools = required_tools_raw if isinstance(required_tools_raw, list) else []
    missing_tools = sorted(str(tool) for tool in required_tools if str(tool) not in tool_names)
    scope_raw = data.get("scope")
    scope = scope_raw if isinstance(scope_raw, dict) else {}

    return [
        _check(
            "manifest-contract",
            not missing_keys and data.get("name") == agent.name,
            "required keys present and filename stem matches manifest name"
            if not missing_keys and data.get("name") == agent.name
            else f"missing_keys={missing_keys} manifest_name={data.get('name')!r}",
        ),
        _check(
            "tool-resolution",
            bool(required_tools) and not missing_tools,
            "required_tools resolve through tools/registry.yaml"
            if required_tools and not missing_tools
            else f"missing_tools={missing_tools} required_tools={required_tools}",
        ),
        _check(
            "safety-boundary",
            bool(scope.get("allowed")) and "forbidden" in scope and bool(data.get("safety")),
            "allowed/forbidden scope and safety rules constrain mutation"
            if bool(scope.get("allowed")) and "forbidden" in scope and bool(data.get("safety"))
            else "scope.allowed, scope.forbidden, or safety is missing",
        ),
        _check(
            "validation-artifacts",
            bool(data.get("validation")) and bool(data.get("artifacts")),
            "validation checks and output artifacts are declared"
            if bool(data.get("validation")) and bool(data.get("artifacts"))
            else "validation or artifacts are missing",
        ),
    ]


def _template_checks(agent: AgentRecord) -> list[dict[str, Any]]:
    data = agent.data
    body = str(data.get("body") or "")
    description = str(data.get("description") or "")
    color = data.get("color")
    parse_error = data.get("_frontmatter_error")

    return [
        _check(
            "frontmatter-contract",
            bool(data.get("display_name")) and bool(description),
            "name and description frontmatter fields are present"
            if data.get("display_name") and description
            else "name or description missing from frontmatter",
        ),
        _check(
            "prompt-body",
            len(body.split()) >= 40 and "#" in body,
            "body is substantial enough to probe and mutate safely"
            if len(body.split()) >= 40 and "#" in body
            else "body is too small or lacks a Markdown heading",
        ),
        _check(
            "stable-identity",
            agent.path.stem == agent.name and agent.name == agent.name.lower(),
            "filename stem provides a stable lowercase machine id"
            if agent.path.stem == agent.name and agent.name == agent.name.lower()
            else f"unstable template id {agent.name!r}",
        ),
        _check(
            "frontmatter-parseability",
            isinstance(color, str) and bool(color.strip()) and not parse_error,
            "strict YAML frontmatter and color metadata are parseable"
            if isinstance(color, str) and bool(color.strip()) and not parse_error
            else f"frontmatter parse issue or missing color: {parse_error or 'missing color'}",
        ),
    ]



def _harness_references() -> list[dict[str, Any]]:
    refs = reference_patterns()
    return [
        {
            "id": ref["id"],
            "source": ref["source"],
            "seams": list(ref["seams"]),
            "principles": list(ref["principles"]),
            "harness_implications": list(ref["harness_implications"]),
        }
        for ref in refs.values()
    ]

def _harness(agent: AgentRecord) -> dict[str, Any]:
    source = str(agent.path.as_posix())
    common_guardrails = [
        "Preserve the agent's identity and declared scope.",
        "Do not weaken safety, validation, or artifact requirements.",
        "Prefer prompt/contract clarification before adding dependencies or tools.",
    ]

    if agent.kind == "operational":
        guardrails = common_guardrails + [
            *[str(item) for item in agent.data.get("safety", [])],
            *[str(item) for item in (agent.data.get("scope", {}) or {}).get("forbidden", [])],
        ]
        probes = [
            {
                "id": "manifest-contract",
                "metric": "schema and filename/name consistency",
                "command": "make agent-check",
            },
            {
                "id": "tool-resolution",
                "metric": "all required tools resolve through tools/registry.yaml",
                "command": "python scripts/agent_check.py",
            },
            {
                "id": "role-validation",
                "metric": "declared validation commands prove the role output",
                "command": str((agent.data.get("execution") or {}).get("command", "make verify")),
            },
            {
                "id": "artifact-completeness",
                "metric": "expected outputs are concrete and reviewable",
                "command": "offline-static",
            },
        ]
        objective = f"Improve the {agent.name} role contract without changing repo invariants."
    else:
        guardrails = common_guardrails + [
            "Keep YAML frontmatter parseable with name, description, and color metadata.",
            "Keep the filename stem as the stable machine id.",
            "Do not remove domain-specific deliverable templates from the persona body.",
        ]
        probes = [
            {
                "id": "frontmatter-contract",
                "metric": "required Claude-style frontmatter fields parse",
                "command": "offline-static",
            },
            {
                "id": "prompt-body",
                "metric": "body contains a substantial Markdown persona contract",
                "command": "offline-static",
            },
            {
                "id": "stable-identity",
                "metric": "stable lowercase machine id derived from filename",
                "command": "offline-static",
            },
            {
                "id": "frontmatter-parseability",
                "metric": "UI metadata remains parseable after mutation",
                "command": "offline-static",
            },
        ]
        objective = f"Improve the {agent.name} persona while preserving its specialist identity."

    return {
        "agent": agent.name,
        "kind": agent.kind,
        "source": source,
        "runtime": "offline-static",
        "objective": objective,
        "mutation_scope": [source],
        "guardrails": [rule for rule in guardrails if rule],
        "reference_patterns": _harness_references(),
        "probes": probes,
    }


def evaluate_agent(agent: AgentRecord, *, tool_names: set[str]) -> dict[str, Any]:
    """Build and evaluate the deterministic self-evolution harness for one agent."""

    checks = (
        _manifest_checks(agent, tool_names)
        if agent.kind == "operational"
        else _template_checks(agent)
    )
    passed = sum(1 for item in checks if item["passed"])
    total = len(checks)
    suggestions = [
        f"Fix {item['id']}: {item['detail']}" for item in checks if not item["passed"]
    ]
    return {
        "harness": _harness(agent),
        "checks": checks,
        "passed": passed,
        "total": total,
        "pass_rate": round(passed / total, 4) if total else 0.0,
        "suggestions": suggestions,
    }


def build_report(root: Path | str = ".", *, include_templates: bool = True) -> dict[str, Any]:
    """Return a self-evolution harness report for every discovered agent."""

    root_path = Path(root)
    records = discover_agents(root_path, include_templates=include_templates)
    tool_names = _tool_names(root_path)
    agents = {record.name: evaluate_agent(record, tool_names=tool_names) for record in records}

    probes_total = sum(payload["total"] for payload in agents.values())
    probes_passed = sum(payload["passed"] for payload in agents.values())
    without_harness = sum(1 for payload in agents.values() if not payload["harness"].get("probes"))
    return {
        "schema_version": "agent-self-evolve.v1",
        "reference_patterns": reference_patterns(),
        "summary": {
            "agents": len(agents),
            "operational_agents": sum(1 for record in records if record.kind == "operational"),
            "template_agents": sum(1 for record in records if record.kind == "template"),
            "agents_without_harness": without_harness,
            "probes_total": probes_total,
            "probes_passed": probes_passed,
            "probe_pass_rate": round(probes_passed / probes_total, 4) if probes_total else 0.0,
        },
        "agents": agents,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build an offline self-evolution harness for each repo agent."
    )
    parser.add_argument("--root", default=".", help="repository root (default: cwd)")
    parser.add_argument(
        "--no-templates",
        action="store_true",
        help="only include operational agents/*.agent.yaml manifests",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--write-report", help="write the JSON report to this path")
    parser.add_argument(
        "--fail-under",
        type=float,
        default=None,
        help="exit non-zero if probe_pass_rate is below this threshold",
    )
    args = parser.parse_args(argv)

    report = build_report(args.root, include_templates=not args.no_templates)
    output = json.dumps(report, indent=2, sort_keys=True)

    if args.write_report:
        report_path = Path(args.write_report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(output + "\n", encoding="utf-8")

    if args.json or args.write_report:
        print(output)
    else:
        summary = report["summary"]
        print(
            "agent-self-evolve: "
            f"{summary['agents']} agents, {summary['probes_passed']}/{summary['probes_total']} "
            f"static probes passed ({summary['probe_pass_rate']:.2%})"
        )

    if args.fail_under is not None and report["summary"]["probe_pass_rate"] < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
