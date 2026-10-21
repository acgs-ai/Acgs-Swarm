"""Read-only, separately pinned replay of the original W2 numeric generation."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
from pathlib import Path
import re
import sys

VERSION = "w2-numeric-standalone-auditor-v1"


def pinned(path: Path, expected: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("invalid external SHA256")
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("symlink evidence")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"SHA256 mismatch: {path}")
    return raw


def exact_pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def load_generation(root: Path, manifest: Path, expected: str):
    mapping = json.loads(pinned(manifest, expected), object_pairs_hook=exact_pairs)
    if type(mapping) is not dict or len(mapping) != 803:
        raise ValueError("original 803-input generation manifest required")
    for name, digest in mapping.items():
        if (
            not isinstance(name, str)
            or name.startswith("/")
            or any(part in ("", ".", "..") for part in name.split("/"))
        ):
            raise ValueError("unsafe generation member")
        pinned(root / name, digest)
    actual = {
        str(p.relative_to(root))
        for p in (root / "src/constitutional_swarm").rglob("*.py")
    }
    if not actual or not actual.issubset(mapping):
        raise ValueError("unsealed generation source")
    if any(
        name == "constitutional_swarm" or name.startswith("constitutional_swarm.")
        for name in sys.modules
    ):
        raise ValueError("generation package already imported")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root / "src"))
    module = importlib.import_module(
        "constitutional_swarm.apcc_empirical.w2_numeric_cold"
    )
    if (
        module.__file__ is None
        or Path(module.__file__).resolve()
        != (
            root / "src/constitutional_swarm/apcc_empirical/w2_numeric_cold.py"
        ).resolve()
    ):
        raise ValueError("wrong generation import")
    return module, mapping


def replay_context_class(context_class):
    class ReplayContext(context_class):
        """Initialize replay diagnostics; retain every original validation method."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.progress = {}

    return ReplayContext


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("audit-failure", "verify"))
    for name in ("generation-root", "generation-manifest", "inputs", "path"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in (
        "auditor",
        "generation-manifest",
        "numeric",
        "coverage",
        "acceptance",
        "result",
        "runtime-plan",
    ):
        parser.add_argument("--" + name + "-sha256", required=True)
    args = parser.parse_args()
    try:
        if not sys.flags.isolated or not sys.flags.no_site:
            raise ValueError("fresh isolated -I -S interpreter required")
        pinned(Path(__file__).absolute(), args.auditor_sha256)
        root = args.generation_root.absolute()
        module, mapping = load_generation(
            root, args.generation_manifest.absolute(), args.generation_manifest_sha256
        )
        context = replay_context_class(module.Context)(
            args.inputs.absolute(),
            numeric_sha=args.numeric_sha256,
            coverage_sha=args.coverage_sha256,
            acceptance_sha=args.acceptance_sha256,
        )
        result = module.audit_result(
            args.path.absolute(),
            expected_sha256=args.result_sha256,
            expected_plan_sha256=args.runtime_plan_sha256,
            context=context,
            failure_audit=args.action == "audit-failure",
        )
        for name, digest in mapping.items():
            pinned(root / name, digest)
        pinned(Path(__file__).absolute(), args.auditor_sha256)
        print(
            json.dumps(
                {
                    "status": "verified",
                    "auditor_version": VERSION,
                    "auditor_sha256": args.auditor_sha256,
                    "generation_manifest_sha256": args.generation_manifest_sha256,
                    "action": args.action,
                    "result": result,
                    "campaign_eligible": False,
                },
                sort_keys=True,
            )
        )
        return 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "auditor_version": VERSION,
                    "error": str(error),
                    "campaign_eligible": False,
                }
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
