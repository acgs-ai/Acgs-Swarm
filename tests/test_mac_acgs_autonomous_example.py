"""Guard the precedent-backed codification wiring demonstrated in
``examples/mac_acgs_autonomous_research.py``.

Locks two facts:

1. The default CAMECoordinator+RuleCodifier composition proposes no rules even
   at ceiling (the codifier receives no PrecedentRecords) — if this ever starts
   proposing, the example's adapter rationale is stale and should be revisited.
2. A precedent-backed codifier closes the loop: ceiling + clustered precedents
   -> proposal -> debate -> committed constitutional update, hash verified.
"""

from __future__ import annotations

import importlib.util
import random
import sys
from pathlib import Path

from constitutional_swarm.bittensor.came_coordinator import CAMECoordinator
from constitutional_swarm.mac_acgs_loop import MacAcgsLoop

_EXAMPLE = Path(__file__).parent.parent / "examples" / "mac_acgs_autonomous_research.py"
_spec = importlib.util.spec_from_file_location("mac_acgs_autonomous_research", _EXAMPLE)
assert _spec is not None and _spec.loader is not None
example = importlib.util.module_from_spec(_spec)
sys.modules["mac_acgs_autonomous_research"] = example
_spec.loader.exec_module(example)


def _run_cycles(loop: MacAcgsLoop, codifier=None, cycles: int = 8) -> None:
    rng = random.Random(42)
    for cycle in range(1, cycles + 1):
        if codifier is not None:
            codifier.observe(example.synth_precedent(rng, 2 * cycle))
            codifier.observe(example.synth_precedent(rng, 2 * cycle + 1))
        loop.run_cycle(example.synth_approaches(rng, cycle))


def test_default_wiring_never_proposes_rules_at_ceiling() -> None:
    loop = MacAcgsLoop(came=CAMECoordinator())
    _run_cycles(loop)
    ceilings = [
        e
        for e in loop.audit_log()
        if (e if isinstance(e, dict) else e.__dict__).get("event_type") == "came_cycle"
    ]
    assert ceilings, "expected came_cycle audit events"
    assert loop.constitution_updates() == []


def test_default_codifier_evolve_cycle_never_proposes_rules() -> None:
    """Direct CAMECycleResult companion to the audit-log proxy above.

    Asserts on ``rules_proposed`` itself (not the downstream constitution-update
    proxy) so the explicit-skip branch in ``evolve_cycle`` is covered directly,
    including at cycles where ``ceiling_detected`` is True.
    """
    came = CAMECoordinator()
    rng = random.Random(42)
    ceiling_seen = False
    for cycle in range(1, 9):
        result = came.evolve_cycle(example.synth_approaches(rng, cycle))
        assert result.rules_proposed == []
        ceiling_seen = ceiling_seen or result.ceiling_detected
    assert ceiling_seen, "expected at least one ceiling cycle in this synthetic run"


def test_precedent_backed_codifier_commits_constitutional_update() -> None:
    codifier = example.PrecedentBackedCodifier()
    loop = MacAcgsLoop(came=CAMECoordinator(codifier=codifier))
    loop.add_external_challenger("human-reviewer-1")
    _run_cycles(loop, codifier=codifier)

    updates = loop.constitution_updates()
    assert len(updates) >= 1
    first = updates[0] if isinstance(updates[0], dict) else updates[0].__dict__
    assert first["verdict_outcome"] == "approved"
    assert first["constitutional_hash"] == example.CONSTITUTIONAL_HASH
