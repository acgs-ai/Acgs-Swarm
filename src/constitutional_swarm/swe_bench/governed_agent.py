"""GovernedAgent — post-hoc constitutional validation wrapper.

Wraps any :class:`SWEBenchAgent` so its produced patches pass through a
constitutional validator (``AgentDNA.validate``) before being accepted.
This is the governance layer for **API-driven** SWE-bench agents — the
LatentDNAWrapper-based BODES steering doesn't apply because we don't have
hidden-state access through Anthropic / Vertex / Gemini APIs.

Governance contract
-------------------
For every patch the base agent produces:

1. Empty patch → ``governance_action="no_patch_to_govern"``,
   ``intervention_rate=0.0``, base outcome preserved.
2. Patch contains constitutional violations OR risk_score >= 0.3 →
   ``governance_action="rejected"``, ``intervention_rate=1.0``,
   ``patch=""``, ``success=False``. The violation list and risk score are
   recorded in metadata.
3. Patch is clean → ``governance_action="accepted"``,
   ``intervention_rate=0.0``, base outcome preserved.

In all three cases ``governed=True`` so the CRDT aggregate records the
governance event. The default constitution is :data:`MCFS_ROLE_CONSTITUTION`
(role-drift CWE/OWASP rules); pass any :class:`Constitution` to override.

Why post-hoc, not in-flight
---------------------------
In-flight governance (BODES logit-steering) requires modifying the
generation forward pass, which is impossible for closed-API models. The
post-hoc strategy retains the H1 mission's governance contract — every
artifact is constitutionally validated before entering the swarm CRDT —
without needing logit access. The trade-off is intervention granularity:
we can only reject whole patches, not individual tokens.

For a meaningful governance comparison (governed vs ungoverned), run two
swarm batches with the same instances/models, one with ``--governed``
and one without, then compare resolve-rate, patch-quality, and any
intervention events.
"""

from __future__ import annotations

import logging
from typing import Any

from constitutional_swarm.dna import AgentDNA, Constitution
from constitutional_swarm.eval.monotonic_mas.detectors.mcfs_constitution import (
    MCFS_ROLE_CONSTITUTION,
)
from constitutional_swarm.swe_bench.agent import SWEBenchAgent, SWEPatch

_log = logging.getLogger(__name__)

_DEFAULT_RISK_THRESHOLD = 0.3


class GovernedAgent(SWEBenchAgent):
    """SWEBenchAgent decorator that validates each patch against a constitution.

    Acts like a SWEBenchAgent (forwards ``solve`` semantics) but post-processes
    the result through ``AgentDNA.validate()``. Identifies as governed in the
    SWEPatch (``governed=True``) so SwarmCoordinator's aggregate counts it.

    Parameters
    ----------
    base:
        The underlying agent (Claude/Vertex/Gemini SWE-bench agent).
    constitution:
        Constitution used by the validator. Defaults to
        :data:`MCFS_ROLE_CONSTITUTION`.
    risk_threshold:
        Risk-score threshold above which a patch is rejected even without
        explicit rule violations. Default 0.3 (matches role-drift detector).
    agent_id:
        Identifier passed to AgentDNA — affects logging only.
    """

    def __init__(
        self,
        base: SWEBenchAgent,
        *,
        constitution: Constitution | None = None,
        risk_threshold: float = _DEFAULT_RISK_THRESHOLD,
        agent_id: str = "governed-swe",
    ) -> None:
        # Don't chain super().__init__ — we delegate fully to base.
        self.base = base
        self.constitution = constitution or MCFS_ROLE_CONSTITUTION
        self.risk_threshold = risk_threshold
        self._dna = AgentDNA(
            constitution=self.constitution,
            agent_id=agent_id,
            strict=False,
            risk_scoring=True,
        )
        # Mirror identifying fields so callers that introspect (e.g. logging)
        # see governance-prefixed model names.
        self.model_name = f"governed::{getattr(base, 'model_name', 'unknown')}"
        self.max_new_tokens = getattr(base, "max_new_tokens", 0)
        self.timeout_s = getattr(base, "timeout_s", 0.0)
        # Mark wrapper presence so SWEPatch.governed flips True via the base
        # path even if some caller bypasses our solve() override.
        self.wrapper = self  # type: ignore[assignment]

    def solve(self, task: dict[str, Any]) -> SWEPatch:  # noqa: D401 — keep base API
        result = self.base.solve(task)

        # Defensive: handle empty / errored patches without invoking the validator.
        if not result.patch.strip():
            result.governed = True
            result.intervention_rate = 0.0
            result.metadata = {
                **(result.metadata or {}),
                "governance_action": "no_patch_to_govern",
            }
            return result

        v = self._dna.validate(result.patch)
        violations = list(getattr(v, "violations", ()) or ())
        risk_score = float(getattr(v, "risk_score", 0.0) or 0.0)
        risk_level = getattr(v, "risk_level", "unknown")

        gov_meta: dict[str, Any] = {
            "governance_constitution_hash": getattr(self.constitution, "hash", None)
            or getattr(self.constitution, "id", "unknown"),
            "governance_violation_count": len(violations),
            "governance_violation_rule_ids": [
                getattr(vio, "rule_id", str(vio)) for vio in violations
            ],
            "governance_risk_score": round(risk_score, 4),
            "governance_risk_level": risk_level,
            "governance_risk_threshold": self.risk_threshold,
        }

        if violations or risk_score >= self.risk_threshold:
            _log.info(
                "governance REJECT %s: %d violations, risk=%.3f",
                task.get("instance_id"), len(violations), risk_score,
            )
            return SWEPatch(
                task_id=result.task_id,
                patch="",
                success=False,
                governed=True,
                intervention_rate=1.0,
                duration_s=result.duration_s,
                metadata={
                    **(result.metadata or {}),
                    **gov_meta,
                    "governance_action": "rejected",
                    "pre_governance_patch_length": len(result.patch),
                },
            )

        result.governed = True
        result.intervention_rate = 0.0
        result.metadata = {
            **(result.metadata or {}),
            **gov_meta,
            "governance_action": "accepted",
        }
        return result


__all__ = ["GovernedAgent"]
