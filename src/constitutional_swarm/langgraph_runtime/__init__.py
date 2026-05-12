"""LangGraph-based agent runtime for constitutional_swarm.

OUTER message-passing shell over the MCFS kernel. All math (swarm_ode,
spectral_sphere, merkle_crdt, evolution_log) and constitutional validation
(AgentDNA.validate, BODES) stay authoritative; LangGraph nodes call into
them rather than replace them.

Install: pip install constitutional-swarm[langgraph]
Docs: docs/langgraph_runtime.md
"""
from __future__ import annotations

try:
    import langgraph as _langgraph  # noqa: F401
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False

try:
    import langgraph_swarm as _langgraph_swarm  # noqa: F401
    HAS_LANGGRAPH_SWARM = True
except ImportError:
    HAS_LANGGRAPH_SWARM = False

__all__ = ["HAS_LANGGRAPH", "HAS_LANGGRAPH_SWARM"]
