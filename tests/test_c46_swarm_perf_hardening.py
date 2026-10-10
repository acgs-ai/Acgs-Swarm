"""C46: swarm executor performance work must not change behaviour.

The workflow input digests are bound by the authority (``attach_workflow``
matches on them), so they are pinned to literal golden values captured from the
pre-refactor implementation.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from constitutional_swarm.execution import ExecutionStatus
from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode, workflow_bindings

from tests.gcb_apcc_support import provision_executor_workflow

GOLDEN_DIGESTS = {
    "g1": {
        "a": "6369ef066e922a3111f1417fe434a48b8d3305fbca4510316af8bb3e543403be",
        "b": "e26df526d5e688bfff3ddad638825fc3cb2a745e05df7fac780405c470fe7bd9",
        "c": "90d304f3a8f0290937badd2c0ba37f74235018654479068067b0e31dc20c0fed",
    },
    "g2": {"only": "1878c70210245240ca570cbdafb49de48c23b7b3865fad56a51d8bbc1a86b29a"},
    "empty": {},
}


def _dags() -> dict[str, TaskDAG]:
    g1 = TaskDAG(dag_id="g1")
    for node in (
        TaskNode(node_id="a"),
        TaskNode(node_id="b", title="B", description="d", domain="x", depends_on=("a",)),
        TaskNode(
            node_id="c",
            title='Ünï "q" \n',
            description="日本語",
            domain="d/é",
            required_capabilities=("w", "Z"),
            depends_on=("a", "b"),
            priority=9,
        ),
    ):
        g1 = g1.add_node(node)
    g2 = TaskDAG(dag_id="g2").add_node(
        TaskNode(node_id="only", title="t", required_capabilities=("cap-1",))
    )
    return {"g1": g1, "g2": g2, "empty": TaskDAG(dag_id="empty")}


def _state(node: TaskNode) -> SimpleNamespace:
    return SimpleNamespace(
        status=node.status.value,
        claimed_by=node.claimed_by,
        artifact_id=node.artifact_id,
        attempt_id=None,
    )


class _FakeClient:
    """Authority stand-in recording attach and state reads."""

    def __init__(self, dag: TaskDAG) -> None:
        self.attach_kwargs: dict[str, object] = {}
        self.state_reads = 0
        self.statuses = {
            nid: ("ready" if not node.depends_on else "blocked") for nid, node in dag.nodes.items()
        }

    def _states(self, node_ids: tuple[str, ...]) -> list[SimpleNamespace]:
        return [
            SimpleNamespace(
                status=self.statuses[nid], claimed_by=None, artifact_id=None, attempt_id=None
            )
            for nid in node_ids
        ]

    def attach_workflow(self, **kwargs: object) -> dict[str, SimpleNamespace]:
        self.attach_kwargs = kwargs
        node_ids = tuple(kwargs["nodes"])  # type: ignore[arg-type]
        return dict(zip(node_ids, self._states(node_ids), strict=True))

    def workflow_node_states(self, workflow_id: str, node_ids: tuple[str, ...]):
        self.state_reads += 1
        return self._states(node_ids)


def _executor(dag: TaskDAG) -> tuple[SwarmExecutor, _FakeClient]:
    from constitutional_swarm.capability import CapabilityRegistry

    executor = SwarmExecutor(CapabilityRegistry(), store=None)  # type: ignore[arg-type]
    client = _FakeClient(dag)
    executor._execution_client = client
    executor._policy_version = "1"
    return executor, client


@pytest.mark.parametrize("name", sorted(GOLDEN_DIGESTS))
def test_workflow_bindings_digest_is_byte_identical_to_baseline(name: str) -> None:
    dag = _dags()[name]
    topology, capabilities, digests = workflow_bindings(dag)
    assert digests == GOLDEN_DIGESTS[name]
    assert topology == {nid: n.depends_on for nid, n in dag.nodes.items()}
    assert capabilities == {nid: n.required_capabilities for nid, n in dag.nodes.items()}


@pytest.mark.parametrize("name", sorted(GOLDEN_DIGESTS))
def test_every_consumer_binds_the_golden_digest(name: str) -> None:
    dag = _dags()[name]

    attached, _ = _executor(dag)
    attached.load_dag(dag)
    # load_dag -> attach_workflow
    client = attached._execution_client
    assert client.attach_kwargs["input_digests"] == GOLDEN_DIGESTS[name]  # type: ignore[attr-defined]

    created: dict[str, object] = {}

    class _Admin:
        def create_workflow(self, **kwargs: object) -> None:
            created.update(kwargs)

    provision_executor_workflow(_Admin(), dag, policy_version="1")
    assert created["input_digests"] == GOLDEN_DIGESTS[name]


def test_bench_has_no_private_digest_copy() -> None:
    import constitutional_swarm.bench as bench

    assert bench.workflow_bindings is workflow_bindings
    assert not hasattr(bench, "_workflow_bindings")


def test_load_dag_does_not_mutate_callers_nodes() -> None:
    dag = _dags()["g1"]
    before = {
        nid: (n.status, n.claimed_by, n.artifact_id, dict(n.metadata)) for nid, n in dag.nodes.items()
    }
    executor, _ = _executor(dag)
    executor.load_dag(dag)
    executor.available_tasks("agent")
    snapshot = executor.dag
    assert snapshot is not None
    for node in snapshot.nodes.values():
        node.status = ExecutionStatus.GOVERNED_COMMITTED
        node.metadata["poison"] = True
    after = {
        nid: (n.status, n.claimed_by, n.artifact_id, dict(n.metadata)) for nid, n in dag.nodes.items()
    }
    assert after == before
    assert executor.progress == {"ready": 1, "blocked": 2}


def test_unchanged_authority_state_does_not_rebuild_indexes() -> None:
    dag = _dags()["g1"]
    executor, client = _executor(dag)
    executor.load_dag(dag)
    rebuilds = {"ready": 0, "deps": 0}
    original_ready = executor._rebuild_ready_index
    original_deps = executor._build_dep_index

    def count_ready() -> None:
        rebuilds["ready"] += 1
        original_ready()

    def count_deps() -> None:
        rebuilds["deps"] += 1
        original_deps()

    executor._rebuild_ready_index = count_ready  # type: ignore[method-assign]
    executor._build_dep_index = count_deps  # type: ignore[method-assign]

    for _ in range(5):
        assert [n.node_id for n in executor.available_tasks("agent")] == ["a"]
        assert executor.is_complete is False
        assert executor.progress == {"ready": 1, "blocked": 2}
        assert executor.dag is not None
    assert client.state_reads >= 20  # the authority is still consulted on every read
    assert rebuilds == {"ready": 0, "deps": 0}


def test_external_authority_change_is_still_observed() -> None:
    dag = _dags()["g1"]
    executor, client = _executor(dag)
    executor.load_dag(dag)
    assert [n.node_id for n in executor.available_tasks("agent")] == ["a"]

    client.statuses.update(a="governed_committed", b="ready")
    assert [n.node_id for n in executor.available_tasks("agent")] == ["b"]
    assert executor.progress == {"governed_committed": 1, "ready": 1, "blocked": 1}

    client.statuses.update(b="governed_committed", c="ready")
    assert executor.is_complete is False
    client.statuses.update(c="governed_committed")
    assert executor.is_complete is True


def test_local_mutation_restores_canonical_ready_order_on_next_read() -> None:
    dag = TaskDAG(dag_id="wide")
    for nid in ("n0", "n1", "n2", "n3"):
        dag = dag.add_node(TaskNode(node_id=nid))
    executor, _ = _executor(dag)
    executor.load_dag(dag)
    # Simulate claim's swap-remove of n1 (authority still reports ready): the
    # next read must rebuild to canonical DAG order, exactly as before.
    executor._ready_list[1], executor._ready_list[3] = (
        executor._ready_list[3],
        executor._ready_list[1],
    )
    executor._indexes_dirty = True
    assert [n.node_id for n in executor.available_tasks("agent")] == ["n0", "n1", "n2", "n3"]


def test_hot_path_timing_is_reported_not_asserted(capsys: pytest.CaptureFixture[str]) -> None:
    """Informational only: prints sync cost for a 500-node chain (no assertions on time)."""
    import time

    dag = TaskDAG(dag_id="chain")
    previous: tuple[str, ...] = ()
    for i in range(500):
        dag = dag.add_node(TaskNode(node_id=f"t{i}", depends_on=previous))
        previous = (f"t{i}",)
    executor, _ = _executor(dag)
    executor.load_dag(dag)
    start = time.perf_counter()
    for _ in range(200):
        executor.progress  # noqa: B018
    elapsed = time.perf_counter() - start
    print(f"200 unchanged progress reads on 500 nodes: {elapsed * 1000:.1f} ms")
    assert executor.progress["ready"] == 1
