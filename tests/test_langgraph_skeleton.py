"""Skeleton smoke test for the langgraph_runtime package."""
from __future__ import annotations

import importlib


def test_module_imports_without_extra():
    module = importlib.import_module("constitutional_swarm.langgraph_runtime")
    assert hasattr(module, "HAS_LANGGRAPH")
    assert hasattr(module, "HAS_LANGGRAPH_SWARM")
    assert isinstance(module.HAS_LANGGRAPH, bool)
    assert isinstance(module.HAS_LANGGRAPH_SWARM, bool)


def test_has_langgraph_consistent_with_import():
    from constitutional_swarm import langgraph_runtime
    try:
        import langgraph  # noqa: F401
        actual = True
    except ImportError:
        actual = False
    assert langgraph_runtime.HAS_LANGGRAPH is actual


def test_has_langgraph_swarm_consistent_with_import():
    from constitutional_swarm import langgraph_runtime
    try:
        import langgraph_swarm  # noqa: F401
        actual = True
    except ImportError:
        actual = False
    assert langgraph_runtime.HAS_LANGGRAPH_SWARM is actual
