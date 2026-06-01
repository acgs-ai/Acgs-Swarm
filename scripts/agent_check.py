#!/usr/bin/env python3
"""Agent self-check: prove the repo is agent-operable.

Validates the tool registry, the agent registry, their cross-references, and
the presence of the required understanding docs. Runs fully offline and needs
only ``pyyaml`` + ``jsonschema`` (both in the dev venv) — the package itself
need not be installed.

Run via ``make agent-check`` or directly::

    uv run --no-sync python scripts/agent_check.py

Exit code is 0 only when every check passes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent

TOOL_REGISTRY = ROOT / "tools" / "registry.yaml"
TOOL_SCHEMA = ROOT / "tools" / "schemas" / "registry.schema.json"
AGENTS_DIR = ROOT / "agents"
AGENT_SCHEMA = AGENTS_DIR / "schemas" / "agent.schema.json"

# Required root docs (the Project Understanding Layer + blocker ledger).
REQUIRED_DOCS = [
    "README.md",
    "ARCHITECTURE.md",
    "PROJECT_MAP.md",
    "TOOLS.md",
    "TASKS.md",
    "DECISIONS.md",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "BLOCKERS.md",
]


class Report:
    """Collects PASS/FAIL lines and tracks overall success."""

    def __init__(self) -> None:
        self.ok = True

    def check(self, passed: bool, label: str, detail: str = "") -> bool:
        mark = "PASS" if passed else "FAIL"
        suffix = f" — {detail}" if detail else ""
        print(f"  [{mark}] {label}{suffix}")
        if not passed:
            self.ok = False
        return passed


def _load_yaml(path: Path) -> object:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _schema_errors(instance: object, schema: dict) -> list[str]:
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
    out = []
    for err in errors:
        loc = "/".join(str(p) for p in err.path) or "<root>"
        out.append(f"{loc}: {err.message}")
    return out


def check_tool_registry(report: Report) -> set[str]:
    """Validate the tool registry; return the set of tool names."""
    print("Tool registry:")
    if not report.check(TOOL_REGISTRY.exists(), f"{TOOL_REGISTRY.name} exists"):
        return set()
    if not report.check(TOOL_SCHEMA.exists(), f"{TOOL_SCHEMA.name} exists"):
        return set()

    data = _load_yaml(TOOL_REGISTRY)
    schema = _load_json(TOOL_SCHEMA)
    errors = _schema_errors(data, schema)
    report.check(not errors, "registry conforms to schema",
                 "; ".join(errors[:5]) if errors else "")
    if errors:
        return set()

    tools = {t["name"]: t for t in data["tools"]}
    report.check(len(tools) == len(data["tools"]), "tool names are unique")

    # Referenced runbooks must exist.
    for name, tool in tools.items():
        rb = tool.get("runbook")
        if rb:
            report.check((ROOT / rb).exists(), f"runbook for '{name}' exists", rb)
    return set(tools)


def check_agent_registry(report: Report, tool_names: set[str]) -> None:
    print("Agent registry:")
    if not report.check(AGENT_SCHEMA.exists(), f"{AGENT_SCHEMA.name} exists"):
        return
    schema = _load_json(AGENT_SCHEMA)

    manifests = sorted(AGENTS_DIR.glob("*.agent.yaml"))
    if not report.check(bool(manifests), "at least one agent manifest exists"):
        return

    for path in manifests:
        data = _load_yaml(path)
        errors = _schema_errors(data, schema)
        if not report.check(not errors, f"{path.name} conforms to schema",
                            "; ".join(errors[:3]) if errors else ""):
            continue
        # Name must match filename stem (foo.agent.yaml -> foo).
        stem = path.name[: -len(".agent.yaml")]
        report.check(data["name"] == stem, f"{path.name} name matches filename",
                     f"name={data['name']!r} stem={stem!r}")
        # Every required tool must exist in the tool registry.
        missing = [t for t in data["required_tools"] if t not in tool_names]
        report.check(not missing, f"{path.name} required_tools resolve",
                     f"unknown: {missing}" if missing else "")


def check_docs(report: Report) -> None:
    print("Documentation completeness:")
    for name in REQUIRED_DOCS:
        path = ROOT / name
        exists = path.exists() and path.stat().st_size > 0
        report.check(exists, f"{name} present and non-empty")


def main() -> int:
    print("=== agent-check: repo agent-operability gate ===\n")
    report = Report()
    tool_names = check_tool_registry(report)
    print()
    check_agent_registry(report, tool_names)
    print()
    check_docs(report)
    print()
    if report.ok:
        print("agent-check: ALL CHECKS PASSED")
        return 0
    print("agent-check: FAILURES DETECTED (see [FAIL] lines above)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
