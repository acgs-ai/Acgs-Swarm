"""Bounded, no-inference verification entry point; never discover the root suite."""

import argparse
import ast
import importlib.abc
import json
import os
import sys
from pathlib import Path

BLOCKED = frozenset(
    {
        "constitutional_swarm",
        "torch",
        "transformers",
        "tokenizers",
        "bittensor",
        "laya",
        "sglang",
        "gepa",
        "graphiti_core",
        "langmem",
        "mem0",
        "sentence_transformers",
        "openai",
        "anthropic",
        "huggingface_hub",
        "datasets",
        "tensorflow",
        "jax",
        "litellm",
    }
)


class NoInference(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in BLOCKED:
            raise ImportError(f"No-inference fixture runner forbids {fullname}")


def import_inventory(root):
    inventory = {}
    for folder in ("offline_foundations", "document_workspace"):
        for file in sorted((root / folder).rglob("*.py")):
            if "__pycache__" in file.parts:
                continue
            imports = set()
            for node in ast.walk(ast.parse(file.read_text(), filename=str(file))):
                if isinstance(node, ast.Import):
                    imports.update(n.name for n in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    imports.add(node.module or "")
            if any(name.split(".")[0] in BLOCKED for name in imports):
                raise RuntimeError(f"Forbidden static import in {file}")
            inventory[str(file.relative_to(root))] = sorted(imports)
    return inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--foundations-only", action="store_true")
    parser.add_argument("--postgresql-parity", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    args.output.mkdir(parents=True, exist_ok=True)
    inventory = import_inventory(root)
    already = sorted(name for name in sys.modules if name.split(".")[0] in BLOCKED)
    if already:
        raise RuntimeError(f"Runner started with forbidden modules loaded: {already}")
    sys.meta_path.insert(0, NoInference())
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    import pytest

    folders = [str(root / "offline_foundations/tests")]
    if args.postgresql_parity:
        if not os.environ.get("ACGS_T6_TEST_DSN"):
            raise RuntimeError(
                "Real PostgreSQL test DSN required; no mock qualification"
            )
        folders.append(str(root / "offline_foundations/postgres_tests"))
    if not args.foundations_only:
        folders.append(str(root / "document_workspace/tests"))
    status = pytest.main(
        [
            *folders,
            "-c",
            str(root / "offline_foundations/pytest.ini"),
            "-v",
            "--tb=short",
            "-o",
            f"pythonpath={root}",
            f"--junitxml={args.output / 'bounded-tests.xml'}",
        ]
    )
    loaded = sorted(name for name in sys.modules if name.split(".")[0] in BLOCKED)
    result = {
        "mode": "recorded_fixture_only",
        "pytest_exit_code": int(status),
        "explicit_test_directories": folders,
        "static_imports": inventory,
        "forbidden_roots": sorted(BLOCKED),
        "forbidden_modules_loaded": loaded,
        "runtime_import_guard": "active",
        "model_calls_executed": 0,
        "backend_parity": "real_postgresql_and_sqlite_fixtures"
        if args.postgresql_parity and status == 0
        else "unqualified"
        if args.postgresql_parity
        else "unrun",
        "model_quality": "unqualified",
        "root_suite_discovered": False,
    }
    (args.output / "import-audit.json").write_text(json.dumps(result, indent=2) + "\n")
    raise SystemExit(status or bool(loaded))


if __name__ == "__main__":
    main()
