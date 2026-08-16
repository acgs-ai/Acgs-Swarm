#!/usr/bin/env python3
"""Install the built wheel into a blank venv and assert packaging isolation.

This does not reuse the project ``.venv``. It creates a temporary virtualenv
from the requested interpreter, installs only the built wheel, then checks:

* ``pip check``
* ``import constitutional_swarm``
* eager façade symbols
* the three console-script ``--help`` commands
* default import graph (no numpy / research / sidecar modules)
* a controlled lazy compatibility import
* a missing-extra error for an optional feature
* installed Requires-Dist metadata (numpy/braintrust not in core)
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_MODULES = (
    "numpy",
    "braintrust",
    "bittensor",
    "torch",
    "langgraph",
    "constitutional_swarm.mac_acgs_loop",
    "constitutional_swarm.merkle_crdt",
    "constitutional_swarm.manifold",
    "constitutional_swarm.swe_bench",
    "constitutional_swarm.latent_dna",
    "constitutional_swarm.swarm_ode",
    "constitutional_swarm.eval",
    "constitutional_swarm.forensic_benchmark",
    "constitutional_swarm.bench",
)
FACADE_SYMBOLS = (
    "AgentDNA",
    "ConstitutionalMesh",
    "DAGCompiler",
    "JSONLSettlementStore",
    "SQLiteSettlementStore",
    "SwarmExecutor",
    "PROFILE_VERSION",
    "verify_bundle",
)
CONSOLE_SCRIPTS = (
    "acgs-swarm",
    "acgs-verify-receipts",
    "acgs-agent-self-evolve",
)


def run(
    cmd: list[str], *, env: dict[str, str] | None = None, cwd: Path | None = None
) -> str:
    completed = subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
    )
    return completed.stdout


def find_interpreter(requested: str) -> str:
    if Path(requested).exists():
        return requested
    found = shutil.which(requested)
    if found:
        return found
    # uv-managed CPython, if present
    try:
        out = run(["uv", "python", "find", requested], cwd=ROOT)
        path = out.strip()
        if path and Path(path).exists():
            return path
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    raise SystemExit(f"interpreter not found: {requested}")


def build_wheel(out_dir: Path) -> Path:
    run(["uv", "build", "--wheel", "--out-dir", str(out_dir)], cwd=ROOT)
    wheels = sorted(out_dir.glob("constitutional_swarm-*.whl"))
    if not wheels:
        raise SystemExit(f"uv build produced no wheel in {out_dir}")
    return wheels[-1]


def metadata_requires(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as archive:
        names = [name for name in archive.namelist() if name.endswith("METADATA")]
        if not names:
            raise SystemExit("wheel has no METADATA")
        text = archive.read(names[0]).decode("utf-8")
    return [
        line.split(":", 1)[1].strip()
        for line in text.splitlines()
        if line.startswith("Requires-Dist:")
    ]


def assert_core_requires(requires_dist: list[str]) -> None:
    core: list[str] = []
    extras: list[str] = []
    for item in requires_dist:
        if "extra ==" in item:
            extras.append(item)
        else:
            core.append(item)
    core_blob = "\n".join(core).lower()
    extra_blob = "\n".join(extras).lower()
    if "numpy" in core_blob:
        raise SystemExit(f"numpy leaked into core Requires-Dist: {core}")
    if "braintrust" in core_blob:
        raise SystemExit(f"braintrust leaked into core Requires-Dist: {core}")
    if "numpy" not in extra_blob:
        raise SystemExit(f"numpy missing from extras Requires-Dist: {extras}")
    if "braintrust" not in extra_blob:
        raise SystemExit(f"braintrust missing from extras Requires-Dist: {extras}")
    print("METADATA core/extras isolation OK")


def isolate_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in ("VIRTUAL_ENV", "PYTHONPATH", "UV_PROJECT", "UV_PROJECT_ENVIRONMENT"):
        env.pop(key, None)
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def install_wheel(python: str, wheel: Path, venv_dir: Path) -> Path:
    run([python, "-m", "venv", str(venv_dir)], env=isolate_env())
    venv_python = venv_dir / ("Scripts" if os.name == "nt" else "bin") / "python"
    run(
        [str(venv_python), "-m", "pip", "install", "--no-cache-dir", str(wheel)],
        env=isolate_env(),
    )
    return venv_python


def verify_installed(venv_python: Path) -> None:
    env = isolate_env()
    run([str(venv_python), "-m", "pip", "check"], env=env)
    print("pip check OK")

    snippet = f"""
import sys
import constitutional_swarm
from constitutional_swarm import {", ".join(FACADE_SYMBOLS)}
assert constitutional_swarm.PROFILE_VERSION.startswith("acgs.local.intoto-dsse-shaped")
leaked = [name for name in {FORBIDDEN_MODULES!r} if name in sys.modules]
if leaked:
    raise SystemExit("default import loaded forbidden modules: " + ", ".join(leaked))
print("import+facade OK")
"""
    print(run([str(venv_python), "-c", snippet], env=env), end="")

    bindir = venv_python.parent
    for script in CONSOLE_SCRIPTS:
        run([str(bindir / script), "--help"], env=env)
        print(f"{script} --help OK")

    lazy = """
from constitutional_swarm import EvolutionLog
assert EvolutionLog.__name__ == "EvolutionLog"
print("lazy compatibility import OK")
"""
    print(run([str(venv_python), "-c", lazy], env=env), end="")

    missing = """
try:
    import constitutional_swarm.latent_dna  # noqa: F401
except ImportError as exc:
    text = str(exc)
    if "research" not in text and "torch" not in text:
        raise SystemExit("missing-extra error was not actionable: " + text)
    print("missing extra error OK")
else:
    raise SystemExit("latent_dna imported without the research extra")
"""
    print(run([str(venv_python), "-c", missing], env=env), end="")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python",
        action="append",
        dest="pythons",
        help="Interpreter or uv python spec (repeatable). Default: current + 3.11 if found.",
    )
    parser.add_argument(
        "--wheel",
        help="Use an existing wheel instead of building.",
    )
    parser.add_argument(
        "--metadata-only",
        action="store_true",
        help="Only inspect wheel METADATA; do not create a venv.",
    )
    return parser.parse_args()


def default_pythons() -> list[str]:
    chosen = [sys.executable]
    for candidate in ("3.11", "python3.11"):
        try:
            found = find_interpreter(candidate)
        except SystemExit:
            continue
        if Path(found).resolve() != Path(sys.executable).resolve():
            chosen.append(found)
            break
    return chosen


def main() -> int:
    args = parse_args()
    with tempfile.TemporaryDirectory(prefix="acgs-swarm-wheel-") as tmp:
        tmp_path = Path(tmp)
        wheel = Path(args.wheel) if args.wheel else build_wheel(tmp_path / "dist")
        print(f"wheel: {wheel}")
        assert_core_requires(metadata_requires(wheel))
        if args.metadata_only:
            return 0
        pythons = args.pythons or default_pythons()
        for spec in pythons:
            interpreter = find_interpreter(spec)
            version = run(
                [interpreter, "-c", "import sys; print(sys.version.split()[0])"]
            )
            print(f"\n=== isolated install on {interpreter} ({version.strip()}) ===")
            venv_dir = tmp_path / f"venv-{version.strip()}"
            venv_python = install_wheel(interpreter, wheel, venv_dir)
            # Prove the venv is not the project environment.
            if (
                Path(sys.prefix).resolve()
                == Path(
                    run(
                        [str(venv_python), "-c", "import sys; print(sys.prefix)"]
                    ).strip()
                ).resolve()
            ):
                raise SystemExit(
                    "blank venv resolved to the current interpreter prefix"
                )
            verify_installed(venv_python)
        print("\nisolated wheel gate OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
