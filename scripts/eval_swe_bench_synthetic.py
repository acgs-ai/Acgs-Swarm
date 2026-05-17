"""Synthetic downstream evaluator for the constitutional swarm on SWE-bench-shaped tasks.

Why synthetic?
--------------
The real SWE-bench Lite harness requires Docker, a patched model, and ~tens of
GB of images — out of scope for in-process autoresearch. This evaluator is a
faithful stand-in that exercises the *plumbing* we actually want to optimize:

  - agents have hidden, domain-specific competencies (π_a(d) → success probability)
  - tasks carry a synthetic ``domain`` tag derived from instance_id
  - the swarm learns a per-(agent,domain) trust estimate via ``ConstitutionalMesh``
    and projects it onto the ``SpectralSphereManifold``
  - the projected trust matrix drives task routing via
    ``SwarmCoordinator.run_in_memory(routing_weights=...)``

The evaluator reports the ``swarm_resolve_rate`` against a ``round_robin``
baseline, plus the *improvement lift* as the headline fitness. This means a
mutation that improves trust-matrix dynamics (e.g. the EMA smoothing added in
commits 56f1b9f / 64a87d1) will produce a measurable downstream signal — the
plumbing gap documented in .omc/specs/deep-interview-autoresearch-trust-convergence.md
is closed.

Fitness = mean lift over seeds. Pass = lift >= 0 on every seed (no regression).
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from constitutional_swarm.manifold import GovernanceManifold  # noqa: E402
from constitutional_swarm.spectral_sphere import SpectralSphereManifold  # noqa: E402
from constitutional_swarm.swe_bench.agent import SWEBenchAgent  # noqa: E402
from constitutional_swarm.swe_bench.swarm_coordinator import SwarmCoordinator  # noqa: E402

_DOMAINS = ("django", "numpy", "sympy", "flask")


def _domain_of(instance_id: str) -> str:
    return instance_id.split("-", 1)[0]


class _CompetencyAgent(SWEBenchAgent):
    """Agent with hidden per-domain success probabilities.

    ``competency[d]`` is the probability of solving a task from domain ``d``.
    Success is drawn deterministically from ``rng``.
    """

    def __init__(self, agent_id: int, competency: dict[str, float], rng: random.Random) -> None:
        super().__init__()
        self.agent_id = agent_id
        self.competency = competency
        self._rng = rng

    def _generate_patch(self, task: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        d = _domain_of(task.get("instance_id", ""))
        p = self.competency.get(d, 0.0)
        if self._rng.random() < p:
            return "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-x\n+y\n", {"intervention_rate": 0.0}
        return "", {"intervention_rate": 0.0}


def _make_tasks(n: int, rng: random.Random) -> list[dict[str, Any]]:
    tasks = []
    for i in range(n):
        d = _DOMAINS[rng.randrange(len(_DOMAINS))]
        tasks.append(
            {
                "instance_id": f"{d}-{i}",
                "problem_statement": f"Task {i} in {d}",
                "patch": "",
                "FAIL_TO_PASS": [],
            }
        )
    return tasks


def _make_agents(n_agents: int, rng: random.Random) -> list[_CompetencyAgent]:
    """Each agent is a specialist: high competency in one domain, low elsewhere."""
    agents = []
    for i in range(n_agents):
        primary = _DOMAINS[i % len(_DOMAINS)]
        competency = {d: 0.15 for d in _DOMAINS}
        competency[primary] = 0.90
        agents.append(_CompetencyAgent(i, competency, rng))
    return agents


def _warmup_trust(
    agents: list[_CompetencyAgent],
    manifold: SpectralSphereManifold,
    warmup_rng: random.Random,
    *,
    warmup_tasks_per_agent: int = 8,
) -> None:
    """Populate the manifold with observed (agent, task) success signal.

    Each agent solves a handful of tasks from each domain; per-domain success
    rates are accumulated into the raw trust matrix (agent i vs ``task_domain``
    pseudo-agent j := domain index). We then project onto the spectral sphere.
    """
    for i, agent in enumerate(agents):
        for d_idx, domain in enumerate(_DOMAINS):
            if d_idx >= manifold.num_agents or i >= manifold.num_agents:
                continue
            successes = 0
            for _ in range(warmup_tasks_per_agent):
                task = {
                    "instance_id": f"{domain}-warm",
                    "problem_statement": "",
                    "patch": "",
                    "FAIL_TO_PASS": [],
                }
                result = agent._generate_patch(task)
                if result[0].strip():
                    successes += 1
            rate = successes / warmup_tasks_per_agent
            manifold.update_trust(i, d_idx, rate)
    _ = manifold.project()


def _trust_to_routing_weights(
    manifold: SpectralSphereManifold,
    tasks: list[dict[str, Any]],
    n_agents: int,
) -> list[list[float]]:
    """Project the trust matrix onto an n_agents × n_tasks routing matrix.

    weight[i][j] = projected_trust[i][domain_index(task_j)].
    """
    projection = manifold.project()
    # Tuple-of-tuples; index it directly.
    matrix = projection.matrix
    weights: list[list[float]] = []
    for i in range(n_agents):
        row = []
        for task in tasks:
            d_idx = _DOMAINS.index(_domain_of(task["instance_id"]))
            if d_idx < manifold.num_agents and i < manifold.num_agents:
                row.append(matrix[i][d_idx])
            else:
                row.append(0.0)
        weights.append(row)
    return weights


def _governance_to_routing_weights(
    manifold: GovernanceManifold,
    tasks: list[dict[str, Any]],
    n_agents: int,
) -> list[list[float]]:
    """Project the Sinkhorn/Birkhoff control onto task routing weights."""
    matrix = manifold.trust_matrix
    return [
        [
            matrix[i][_DOMAINS.index(_domain_of(task["instance_id"]))]
            if i < manifold.num_agents
            else 0.0
            for task in tasks
        ]
        for i in range(n_agents)
    ]


def _warmup_sinkhorn_trust(
    agents: list[_CompetencyAgent],
    *,
    warmup_tasks_per_agent: int,
    collapse_cycles: int = 10,
) -> GovernanceManifold:
    """Build the explicit Sinkhorn-CRDT research-control routing baseline.

    This intentionally uses ``GovernanceManifold`` and repeated composition to
    preserve the Birkhoff/Sinkhorn uniformity-collapse control rather than
    silently replacing it with SpectralSphere behavior.
    """
    manifold = GovernanceManifold(num_agents=max(len(agents), len(_DOMAINS)))
    for i, agent in enumerate(agents):
        for d_idx, domain in enumerate(_DOMAINS):
            successes = 0
            for _ in range(warmup_tasks_per_agent):
                task = {
                    "instance_id": f"{domain}-warm",
                    "problem_statement": "",
                    "patch": "",
                    "FAIL_TO_PASS": [],
                }
                result = agent._generate_patch(task)
                if result[0].strip():
                    successes += 1
            manifold.update_trust(i, d_idx, successes / warmup_tasks_per_agent)
    current = manifold
    for _ in range(collapse_cycles):
        current = current.compose(manifold)
    return current


def _oracle_routing_weights(
    agents: list[_CompetencyAgent],
    tasks: list[dict[str, Any]],
) -> list[list[float]]:
    """Use hidden competencies as a centralized upper-bound routing matrix."""
    return [
        [agent.competency.get(_domain_of(task["instance_id"]), 0.0) for task in tasks]
        for agent in agents
    ]


def _uniform_routing_weights(n_agents: int, n_tasks: int) -> list[list[float]]:
    """Collapsed/flat trust table; coordinator tie-breaking routes to agent 0."""
    return [[1.0 for _ in range(n_tasks)] for _ in range(n_agents)]


def _assignments_from_weights(weights: list[list[float]]) -> list[int]:
    if not weights:
        return []
    assignments: list[int] = []
    for j in range(len(weights[0])):
        best_i = 0
        best_w = weights[0][j]
        for i in range(1, len(weights)):
            if weights[i][j] > best_w:
                best_w = weights[i][j]
                best_i = i
        assignments.append(best_i)
    return assignments


def _routing_diversity_pct(assignments: list[int], n_agents: int) -> float:
    """Normalized assignment entropy as a 0-100 routing-specialization score."""
    if not assignments or n_agents <= 1:
        return 0.0
    counts = [0 for _ in range(n_agents)]
    for agent_id in assignments:
        counts[agent_id] += 1
    entropy = 0.0
    total = len(assignments)
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log(p)
    return 100.0 * entropy / math.log(n_agents)


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def run(seed: int, n_agents: int, n_tasks: int, warmup: int) -> dict[str, Any]:
    if warmup < 1:
        msg = "warmup must be at least 1 task per agent"
        raise ValueError(msg)

    rng_tasks = random.Random(seed)
    rng_agents = random.Random(seed + 1000)

    # Two parallel agent populations so round-robin and swarm evaluations are
    # drawn from the same underlying distribution but independent RNG streams.
    agents_swarm = _make_agents(n_agents, random.Random(seed + 2000))
    agents_rr = _make_agents(n_agents, random.Random(seed + 3000))
    agents_flat = _make_agents(n_agents, random.Random(seed + 3000))
    agents_sinkhorn = _make_agents(n_agents, random.Random(seed + 3000))
    agents_oracle = _make_agents(n_agents, random.Random(seed + 4000))

    tasks = _make_tasks(n_tasks, rng_tasks)

    # Manifold size must cover both agents and domains.
    manifold = SpectralSphereManifold(num_agents=max(n_agents, len(_DOMAINS)))
    _warmup_trust(agents_swarm, manifold, rng_agents, warmup_tasks_per_agent=warmup)
    weights = _trust_to_routing_weights(manifold, tasks, n_agents)
    flat_weights = _uniform_routing_weights(n_agents, len(tasks))
    sinkhorn_manifold = _warmup_sinkhorn_trust(
        agents_sinkhorn,
        warmup_tasks_per_agent=warmup,
    )
    sinkhorn_weights = _governance_to_routing_weights(sinkhorn_manifold, tasks, n_agents)
    oracle_weights = _oracle_routing_weights(agents_oracle, tasks)

    coord_swarm = SwarmCoordinator(agents_swarm)
    coord_rr = SwarmCoordinator(agents_rr)
    coord_flat = SwarmCoordinator(agents_flat)
    coord_sinkhorn = SwarmCoordinator(agents_sinkhorn)
    coord_oracle = SwarmCoordinator(agents_oracle)

    swarm_result = coord_swarm.run_in_memory(tasks, routing_weights=weights)
    rr_result = coord_rr.run_in_memory(tasks)
    flat_result = coord_flat.run_in_memory(tasks, routing_weights=flat_weights)
    sinkhorn_result = coord_sinkhorn.run_in_memory(tasks, routing_weights=sinkhorn_weights)
    oracle_result = coord_oracle.run_in_memory(tasks, routing_weights=oracle_weights)

    swarm_rate = swarm_result["resolve_rate"]
    rr_rate = rr_result["resolve_rate"]
    lift = swarm_rate - rr_rate
    flat_assignments = _assignments_from_weights(flat_weights)
    sinkhorn_assignments = _assignments_from_weights(sinkhorn_weights)
    fedsink_assignments = _assignments_from_weights(weights)
    return {
        "lift": lift,
        "swarm_resolve_rate": swarm_rate,
        "round_robin_resolve_rate": rr_rate,
        "flat_resolve_rate": flat_result["resolve_rate"],
        "sinkhorn_crdt_resolve_rate": sinkhorn_result["resolve_rate"],
        "fedsink_resolve_rate": swarm_rate,
        "centralized_resolve_rate": oracle_result["resolve_rate"],
        "flat_routing_diversity_pct": _routing_diversity_pct(flat_assignments, n_agents),
        "sinkhorn_crdt_routing_diversity_pct": _routing_diversity_pct(
            sinkhorn_assignments, n_agents
        ),
        "fedsink_routing_diversity_pct": _routing_diversity_pct(fedsink_assignments, n_agents),
        "convergence_rounds": math.ceil(math.log2(max(n_agents, 2))),
        "spectral_norm": manifold.spectral_norm,
        "sinkhorn_spectral_bound": sinkhorn_manifold.spectral_bound,
        "is_stable": manifold.is_stable,
        "params": {"seed": seed, "agents": n_agents, "tasks": n_tasks, "warmup": warmup},
    }


def summarize_runs(
    *,
    seeds: list[int],
    n_agents: int,
    n_tasks: int,
    warmup: int,
) -> dict[str, Any]:
    if warmup < 1:
        msg = "warmup must be at least 1 task per agent"
        raise ValueError(msg)

    runs = [run(seed, n_agents, n_tasks, warmup) for seed in seeds]
    payload = {
        "pass": bool(all(r["lift"] >= -1e-9 for r in runs)),
        "score": _mean([r["lift"] for r in runs]),
        "mean_swarm_resolve_rate": _mean([r["swarm_resolve_rate"] for r in runs]),
        "mean_round_robin_resolve_rate": _mean([r["round_robin_resolve_rate"] for r in runs]),
        "round_robin_resolve_rate": _mean([r["round_robin_resolve_rate"] for r in runs]),
        "flat_resolve_rate": _mean([r["flat_resolve_rate"] for r in runs]),
        "sinkhorn_crdt_resolve_rate": _mean([r["sinkhorn_crdt_resolve_rate"] for r in runs]),
        "fedsink_resolve_rate": _mean([r["fedsink_resolve_rate"] for r in runs]),
        "centralized_resolve_rate": _mean([r["centralized_resolve_rate"] for r in runs]),
        "flat_routing_diversity_pct": _mean([r["flat_routing_diversity_pct"] for r in runs]),
        "sinkhorn_crdt_routing_diversity_pct": _mean(
            [r["sinkhorn_crdt_routing_diversity_pct"] for r in runs]
        ),
        "fedsink_routing_diversity_pct": _mean([r["fedsink_routing_diversity_pct"] for r in runs]),
        "convergence_rounds": max(r["convergence_rounds"] for r in runs),
        "official_swebench_claimed": False,
        "official_swe_bench_claimed": False,
        "synthetic_only": True,
        "per_seed": runs,
        "seeds": seeds,
        "task_count": n_tasks,
        "agent_count": n_agents,
    }
    return payload


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--seeds", type=str, default="42,7,13")
    p.add_argument("--agents", type=int, default=4)
    p.add_argument("--tasks", type=int, default=64)
    p.add_argument("--warmup", type=int, default=8)
    args = p.parse_args()
    if args.warmup < 1:
        p.error("--warmup must be at least 1")

    seeds = [int(s) for s in args.seeds.split(",") if s.strip()]
    print(
        json.dumps(
            summarize_runs(
                seeds=seeds,
                n_agents=args.agents,
                n_tasks=args.tasks,
                warmup=args.warmup,
            )
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
