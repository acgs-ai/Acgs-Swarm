from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path

from constitutional_swarm.swe_bench.mini_swe_agent import MiniSWEBenchAgent

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "run_swe_bench_swarm_lite.py"
_SPEC = importlib.util.spec_from_file_location("run_swe_bench_swarm_lite", _SCRIPT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

_OFFICIAL_SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent / "scripts" / "run_official_swarm_swebench.py"
)
_OFFICIAL_SPEC = importlib.util.spec_from_file_location(
    "run_official_swarm_swebench_backend_choices",
    _OFFICIAL_SCRIPT_PATH,
)
assert _OFFICIAL_SPEC is not None and _OFFICIAL_SPEC.loader is not None
_OFFICIAL_MODULE = importlib.util.module_from_spec(_OFFICIAL_SPEC)
_OFFICIAL_SPEC.loader.exec_module(_OFFICIAL_MODULE)


def test_import_runtime_supports_optional_mini_backend() -> None:
    runtime = _MODULE._import_runtime("mini")

    assert runtime["agent_cls"] is MiniSWEBenchAgent
    assert runtime["SwarmCoordinator"].__name__ == "SwarmCoordinator"


def test_make_agents_passes_mini_backend_options_without_running_cli() -> None:
    agents = _MODULE._make_agents(
        model="mini-model",
        timeout_s=3.0,
        count=2,
        agent_cls=MiniSWEBenchAgent,
        agent_kwargs={
            "mini_binary": "mini-custom",
            "extra_args": ["--config", "mini.yaml"],
            "yolo": True,
        },
    )

    assert len(agents) == 2
    assert all(isinstance(agent, MiniSWEBenchAgent) for agent in agents)
    assert agents[0].runner.mini_binary == "mini-custom"
    assert agents[0].runner.model == "mini-model"
    assert agents[0].runner.timeout_s == 3.0
    assert agents[0].runner.extra_args == ["--config", "mini.yaml"]
    assert agents[0].runner.yolo is True


def test_backend_agent_kwargs_are_empty_for_default_codex_backend() -> None:
    args = argparse.Namespace(
        backend="codex",
        mini_binary="ignored",
        mini_extra_arg=["--ignored"],
        mini_yolo=True,
    )

    assert _MODULE._backend_agent_kwargs(args) == {}


def test_backend_agent_kwargs_are_explicit_for_mini_backend() -> None:
    args = argparse.Namespace(
        backend="mini",
        mini_binary="mini-custom",
        mini_extra_arg=["--config", "mini.yaml"],
        mini_yolo=False,
    )

    assert _MODULE._backend_agent_kwargs(args) == {
        "mini_binary": "mini-custom",
        "extra_args": ["--config", "mini.yaml"],
        "yolo": False,
    }


def test_swarm_cli_parser_accepts_mini_backend_without_making_it_default() -> None:
    choices = _backend_choices(_MODULE.build_parser())

    assert choices == ["codex", "claude", "mini"]
    assert _MODULE.build_parser().parse_args([]).backend == "codex"


def test_official_wrapper_parser_accepts_mini_backend_without_making_it_default() -> None:
    choices = _backend_choices(_OFFICIAL_MODULE.build_parser())

    assert choices == ["codex", "claude", "mini"]
    assert _OFFICIAL_MODULE.build_parser().parse_args(["--run-id", "demo"]).backend == "codex"


def _backend_choices(parser: argparse.ArgumentParser) -> list[str] | None:
    for action in parser._actions:
        if action.dest == "backend":
            return action.choices
    return None
