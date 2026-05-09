"""Per-mode catch detectors. Each module exposes a detect_<mode>(trace, governance_enabled) -> (bool, dict)."""

from constitutional_swarm.eval.monotonic_mas.detectors.dedupe import detect_dedupe
from constitutional_swarm.eval.monotonic_mas.detectors.handoff import detect_handoff
from constitutional_swarm.eval.monotonic_mas.detectors.role import detect_role

__all__ = ["detect_dedupe", "detect_handoff", "detect_role"]
