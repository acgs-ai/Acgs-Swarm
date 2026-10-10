"""C45 regression tests: core miscellaneous correctness.

core-research-17: duplicate agent names must not silently shadow each other.
capability-1: domain-scoped routing must not return non-matching agents, and
unregister must not leave empty index entries behind.
core-research-opt-6: ArtifactStore lookups use an id index and resolve
visibility in one locked pass without evaluating guards under the lock.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from constitutional_swarm.agent_self_evolve import build_report, discover_agents
from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.capability import Capability, CapabilityRegistry

# ---------------------------------------------------------------------------
# core-research-17
# ---------------------------------------------------------------------------


def _write_operational(root: Path, stem: str, name: str) -> Path:
    path = root / "agents" / f"{stem}.agent.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"name: {name}\npurpose: test\n", encoding="utf-8")
    return path


def _write_template(root: Path, stem: str) -> Path:
    path = root / "agents" / "templates" / f"{stem}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"---\nname: {stem.title()}\ndescription: test template\n---\nbody\n",
        encoding="utf-8",
    )
    return path


def test_template_sharing_operational_name_is_rejected(tmp_path: Path) -> None:
    operational = _write_operational(tmp_path, "foo", "foo")
    template = _write_template(tmp_path, "foo")

    with pytest.raises(ValueError, match="duplicate agent name 'foo'") as excinfo:
        build_report(tmp_path, include_templates=True)
    assert str(operational) in str(excinfo.value)
    assert str(template) in str(excinfo.value)


def test_two_operational_manifests_declaring_same_name_are_rejected(
    tmp_path: Path,
) -> None:
    _write_operational(tmp_path, "alpha", "shared")
    _write_operational(tmp_path, "beta", "shared")

    with pytest.raises(ValueError, match="duplicate agent name 'shared'"):
        discover_agents(tmp_path, include_templates=False)


def test_unique_names_still_produce_consistent_report(tmp_path: Path) -> None:
    _write_operational(tmp_path, "foo", "foo")
    _write_template(tmp_path, "bar")

    report = build_report(tmp_path, include_templates=True)

    summary = report["summary"]
    assert summary["agents"] == summary["operational_agents"] + summary["template_agents"]
    assert set(report["agents"]) == {"foo", "bar"}


# ---------------------------------------------------------------------------
# capability-1
# ---------------------------------------------------------------------------


def test_domain_scoped_find_best_rejects_non_matching_requirement() -> None:
    reg = CapabilityRegistry()
    reg.register("a", [Capability(name="python", domain="code")])

    assert reg.find_best("rust", domain="code") is None


def test_domain_scoped_find_best_prefers_matching_over_cheaper_non_match() -> None:
    reg = CapabilityRegistry()
    reg.register("cheap", [Capability(name="python", domain="code", cost_per_task=0.001)])
    reg.register("match", [Capability(name="rust", domain="code", cost_per_task=10.0)])

    best = reg.find_best("rust", domain="code", prefer_cheap=True)

    assert best is not None
    assert best[0] == "match"


def test_unregister_drops_emptied_domain_and_name_indexes() -> None:
    reg = CapabilityRegistry()
    reg.register("a", [Capability(name="python", domain="code")])
    reg.register("b", [Capability(name="review", domain="qa")])

    reg.unregister("a")

    assert reg.domains == ["qa"]
    summary = reg.summary()
    assert summary["domains"] == 1
    assert summary["domain_distribution"] == {"qa": 1}
    # The name index has no public listing; an empty leftover key is only visible here.
    assert "python" not in reg._by_name
    assert reg.find_by_domain("code") == []
    assert reg.find_by_name("python") == []


def test_reregister_into_new_domain_drops_old_domain() -> None:
    reg = CapabilityRegistry()
    reg.register("a", [Capability(name="legacy", domain="old")])
    reg.register("a", [Capability(name="current", domain="new")])

    assert reg.domains == ["new"]
    assert set(reg._by_name) == {"current"}  # no public listing of the name index


_WRITERS = 8
_AGENTS_PER_WRITER = 3
_ROUNDS = 300


def _agent_caps(writer: int, slot: int, round_: int) -> list[Capability]:
    # Shared domains/names across writers so concurrent updates hit the same lists.
    return [
        Capability(name=f"skill{(writer + round_) % 3}", domain=f"d{(slot + round_) % 3}"),
        Capability(name=f"skill{(slot + 1) % 3}", domain=f"d{(writer + slot) % 3}"),
    ]


def _hammer_registry(reg: CapabilityRegistry) -> list[BaseException]:
    """Run concurrent register/unregister/find traffic; return reader/writer errors."""
    errors: list[BaseException] = []
    stop = threading.Event()
    start = threading.Barrier(_WRITERS + 4)

    def writer(index: int) -> None:
        try:
            start.wait()
            for round_ in range(_ROUNDS):
                for slot in range(_AGENTS_PER_WRITER):
                    agent_id = f"w{index}-a{slot}"
                    if round_ % 3 == 2:
                        reg.unregister(agent_id)
                    reg.register(agent_id, _agent_caps(index, slot, round_))
        except BaseException as exc:  # pragma: no cover - reported via errors
            errors.append(exc)

    def reader() -> None:
        try:
            start.wait()
            while not stop.is_set():
                reg.find_best("skill1", domain="d1", prefer_cheap=True)
                reg.find_best("skill2")
                reg.summary()
                for domain in reg.domains:
                    reg.find_by_domain(domain)
                for agent_id in reg.agents:
                    reg.get_agent_capabilities(agent_id)
        except BaseException as exc:  # pragma: no cover - reported via errors
            errors.append(exc)

    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        writers = [threading.Thread(target=writer, args=(i,)) for i in range(_WRITERS)]
        readers = [threading.Thread(target=reader) for _ in range(4)]
        for thread in (*writers, *readers):
            thread.start()
        for thread in writers:
            thread.join()
        stop.set()
        for thread in readers:
            thread.join()
    finally:
        sys.setswitchinterval(previous)
    return errors


def _index_inconsistencies(reg: CapabilityRegistry) -> list[str]:
    problems: list[str] = []
    agents = set(reg.agents)
    expected = {
        f"w{writer}-a{slot}" for writer in range(_WRITERS) for slot in range(_AGENTS_PER_WRITER)
    }
    if agents != expected:
        problems.append(f"agents {sorted(agents ^ expected)} differ from expected")
    entries: list[tuple[str, Capability]] = []
    for agent_id in agents:
        for cap in reg.get_agent_capabilities(agent_id):
            entries.append((agent_id, cap))
            if (agent_id, cap) not in reg.find_by_domain(cap.domain):
                problems.append(f"{agent_id}/{cap.name} missing from domain {cap.domain}")
            if (agent_id, cap) not in reg.find_by_name(cap.name):
                problems.append(f"{agent_id}/{cap.name} missing from name index")
    indexed: list[tuple[str, Capability]] = []
    for domain in reg.domains:
        listed = reg.find_by_domain(domain)
        if not listed:
            problems.append(f"empty domain {domain} still listed")
        indexed.extend(listed)
    if sorted(map(repr, indexed)) != sorted(map(repr, entries)):
        problems.append("domain index holds stale or duplicate entries")
    summary = reg.summary()
    if summary["capabilities"] != len(entries) or sum(
        summary["domain_distribution"].values()
    ) != len(entries):
        problems.append(f"summary {summary} disagrees with {len(entries)} registrations")
    return problems


def test_concurrent_register_unregister_find_keeps_indexes_consistent() -> None:
    reg = CapabilityRegistry()

    errors = _hammer_registry(reg)

    assert errors == []
    assert _index_inconsistencies(reg) == []


def test_lookups_return_copies_not_live_internals() -> None:
    reg = CapabilityRegistry()
    reg.register("a", [Capability(name="python", domain="code")])

    reg.find_by_domain("code").clear()
    reg.find_by_name("python").clear()
    reg.get_agent_capabilities("a").clear()
    reg.agents.clear()
    reg.domains.clear()

    assert reg.find_by_domain("code") == [("a", Capability(name="python", domain="code"))]
    assert reg.find_by_name("python") == [("a", Capability(name="python", domain="code"))]
    assert reg.get_agent_capabilities("a") == [Capability(name="python", domain="code")]
    assert reg.agents == ["a"]
    assert reg.domains == ["code"]


def test_register_copies_caller_capability_list() -> None:
    reg = CapabilityRegistry()
    caps = [Capability(name="python", domain="code")]
    reg.register("a", caps)

    caps.append(Capability(name="rust", domain="systems"))

    assert reg.get_agent_capabilities("a") == [Capability(name="python", domain="code")]
    assert reg.find_best("rust") is None
    assert reg.summary()["capabilities"] == 1
    assert reg.domains == ["code"]


# ---------------------------------------------------------------------------
# core-research-opt-6
# ---------------------------------------------------------------------------


class _NoIterDict(dict[Any, Any]):
    def __iter__(self) -> Any:
        raise AssertionError("ArtifactStore.get must not scan every stored artifact")


class _CountingLock:
    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.acquisitions = 0

    def acquire(self, *args: Any, **kwargs: Any) -> bool:
        self.acquisitions += 1
        return bool(self._inner.acquire(*args, **kwargs))

    def release(self) -> None:
        self._inner.release()

    def __enter__(self) -> _CountingLock:
        self.acquire()
        return self

    def __exit__(self, *_: Any) -> None:
        self.release()


def _artifact(artifact_id: str, *, task: str = "t", domain: str = "d") -> Artifact:
    return Artifact(
        artifact_id=artifact_id,
        task_id=task,
        agent_id=f"agent-{artifact_id}",
        content_type="text",
        content=f"content-{artifact_id}",
        domain=domain,
    )


def test_get_without_workflow_uses_id_index_not_full_scan() -> None:
    store = ArtifactStore()
    for index in range(5):
        store.publish(_artifact(f"a{index}"))
    store._artifacts = _NoIterDict(store._artifacts)

    found = store.get("a3")

    assert found is not None
    assert found.artifact_id == "a3"
    assert store.get("missing") is None


def test_get_without_workflow_is_ambiguous_across_workflows() -> None:
    store = ArtifactStore()
    store.publish(_artifact("shared"))
    port = store._bind_governed(workflow_id="w1", seal_id="s1", guard=lambda _aid: True)
    port.publish(_artifact("shared"))

    from constitutional_swarm.governance_errors import GovernanceBypassDenied

    with pytest.raises(GovernanceBypassDenied):
        store.get("shared")
    assert store.get("shared", workflow_id="") is not None
    assert port.get("shared") is not None


def test_count_and_summary_take_store_lock_once() -> None:
    store = ArtifactStore()
    for index in range(4):
        store.publish(_artifact(f"a{index}", domain=f"d{index % 2}"))
    store.revoke("a0")
    counting = _CountingLock(store._lock)
    store._lock = counting  # type: ignore[assignment]

    assert store.count == 3
    assert counting.acquisitions == 1

    counting.acquisitions = 0
    summary = store.summary()
    assert summary == {"total_artifacts": 3, "domains": 2, "agents": 3, "tasks": 1}
    assert counting.acquisitions == 1


def test_get_by_task_takes_store_lock_once() -> None:
    store = ArtifactStore()
    for index in range(4):
        store.publish(_artifact(f"a{index}"))
    counting = _CountingLock(store._lock)
    store._lock = counting  # type: ignore[assignment]

    assert [a.artifact_id for a in store.get_by_task("t")] == ["a0", "a1", "a2", "a3"]
    assert counting.acquisitions == 1


def test_visibility_guards_run_outside_store_lock() -> None:
    store = ArtifactStore()
    publishing = threading.Event()
    publishing.set()

    def guard(_artifact_id: str) -> bool:
        if publishing.is_set():
            return True
        # A guard that re-enters the store must not find the lock held.
        acquired = store._lock.acquire(timeout=1)
        if acquired:
            store._lock.release()
        return acquired

    port = store._bind_governed(workflow_id="w", seal_id="s", guard=guard)
    port.publish(_artifact("g1"))
    port.publish(_artifact("g2"))
    publishing.clear()

    assert store.count == 2
    assert store.summary()["total_artifacts"] == 2
    assert [a.artifact_id for a in store.get_by_task("t", workflow_id="w")] == ["g1", "g2"]
    assert port.get("g1") is not None
    assert store.verify_integrity("g2", workflow_id="w") is True


def test_failing_guard_hides_artifact_in_count_and_summary() -> None:
    store = ArtifactStore()
    publishing = threading.Event()
    publishing.set()

    def guard(artifact_id: str) -> bool:
        if publishing.is_set():
            return True
        if artifact_id == "boom":
            raise RuntimeError("guard failure")
        return artifact_id != "hidden"

    port = store._bind_governed(workflow_id="w", seal_id="s", guard=guard)
    for artifact_id in ("ok", "hidden", "boom"):
        port.publish(_artifact(artifact_id))
    publishing.clear()

    assert store.count == 1
    assert store.summary()["total_artifacts"] == 1
    assert [a.artifact_id for a in store.get_by_task("t", workflow_id="w")] == ["ok"]
