#!/usr/bin/env python3
"""Compatibility wrapper for the packaged agent self-evolution harness CLI."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from constitutional_swarm.agent_self_evolve import (  # noqa: E402
    AgentRecord,
    build_report,
    discover_agents,
    evaluate_agent,
    main,
    reference_patterns,
)

__all__ = [
    "AgentRecord",
    "build_report",
    "discover_agents",
    "evaluate_agent",
    "main",
    "reference_patterns",
]


if __name__ == "__main__":
    raise SystemExit(main())
