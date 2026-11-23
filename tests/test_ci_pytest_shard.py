"""The CI shard selector must partition a collection and detect lost tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import ci_pytest_shard as shard

_NODE_IDS = [f"tests/test_x.py::test_case[{index}]" for index in range(257)]


@pytest.mark.parametrize("shards", (1, 2, 4, 7))
def test_every_node_belongs_to_exactly_one_shard(shards: int) -> None:
    buckets = [
        [node for node in _NODE_IDS if shard.shard_of(node, shards) == index]
        for index in range(shards)
    ]
    assert sorted(node for bucket in buckets for node in bucket) == sorted(_NODE_IDS)
    assert sum(len(bucket) for bucket in buckets) == len(_NODE_IDS)


def test_assignment_ignores_the_rest_of_the_collection() -> None:
    before = {node: shard.shard_of(node, 4) for node in _NODE_IDS}
    grown = [*_NODE_IDS, "tests/test_y.py::test_added"]
    assert {node: shard.shard_of(node, 4) for node in grown if node in before} == before


def test_collection_digest_is_order_independent() -> None:
    assert shard.collection_digest(_NODE_IDS) == shard.collection_digest(_NODE_IDS[::-1])
    assert shard.collection_digest(_NODE_IDS) != shard.collection_digest(_NODE_IDS[1:])


def _write_shards(
    directory: Path,
    shards: int,
    *,
    drop_report: int | None = None,
    skipped_in: int | None = None,
    short_by: int = 0,
) -> None:
    digest = shard.collection_digest(_NODE_IDS)
    for index in range(shards):
        selected = [node for node in _NODE_IDS if shard.shard_of(node, shards) == index]
        manifest = {
            "version": shard.MANIFEST_VERSION,
            "shards": shards,
            "index": index,
            "collected": len(_NODE_IDS),
            "collection_sha256": digest,
            "selected": len(selected),
            "selected_sha256": shard.collection_digest(selected),
        }
        (directory / f"shard-manifest-{index}.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        if index == drop_report:
            continue
        ran = len(selected) - (short_by if index == 0 else 0)
        skipped = 1 if index == skipped_in else 0
        (directory / f"shard-results-{index}.xml").write_text(
            f'<testsuites><testsuite tests="{ran}" skipped="{skipped}" '
            'failures="0" errors="0"/></testsuites>',
            encoding="utf-8",
        )


def test_verify_accepts_complete_coverage(tmp_path: Path) -> None:
    _write_shards(tmp_path, 4)
    assert shard.main(["verify", "--shards", "4", str(tmp_path)]) == 0


@pytest.mark.parametrize(
    "fault",
    (
        {"drop_report": 2},
        {"skipped_in": 1},
        {"short_by": 1},
    ),
)
def test_verify_rejects_lost_or_skipped_tests(tmp_path: Path, fault: dict[str, int]) -> None:
    _write_shards(tmp_path, 4, **fault)
    assert shard.main(["verify", "--shards", "4", str(tmp_path)]) == 1


def test_verify_rejects_a_missing_shard(tmp_path: Path) -> None:
    _write_shards(tmp_path, 4)
    (tmp_path / "shard-manifest-3.json").unlink()
    (tmp_path / "shard-results-3.xml").unlink()
    assert shard.main(["verify", "--shards", "4", str(tmp_path)]) == 1


def test_verify_rejects_disagreeing_collections(tmp_path: Path) -> None:
    _write_shards(tmp_path, 2)
    path = tmp_path / "shard-manifest-1.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["collection_sha256"] = "0" * 64
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(SystemExit):
        shard.main(["verify", str(tmp_path)])
