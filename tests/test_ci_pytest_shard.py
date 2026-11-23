"""The CI shard selector must partition a collection and detect lost tests."""

from __future__ import annotations

import json
import subprocess
import sys
import xml.etree.ElementTree as ET
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
    short_by: int = 0,
    **bad_counts: int,
) -> None:
    """Write manifests and reports; ``bad_counts`` plants e.g. ``skipped=1`` in shard 1."""
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
        }
        (directory / f"shard-manifest-{index}.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        if index == drop_report:
            continue
        ran = len(selected) - (short_by if index == 0 else 0)
        counts = {"skipped": 0, "failures": 0, "errors": 0}
        if index == 1:
            counts.update(bad_counts)
        attributes = " ".join(f'{key}="{value}"' for key, value in counts.items())
        (directory / f"shard-results-{index}.xml").write_text(
            f'<testsuites><testsuite tests="{ran}" {attributes}/></testsuites>',
            encoding="utf-8",
        )


def test_verify_accepts_complete_coverage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_shards(tmp_path, 4)
    assert shard.main(["verify", "--shards", "4", str(tmp_path)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["ok"] is True
    assert summary["collected"] == summary["executed"] == len(_NODE_IDS)


@pytest.mark.parametrize(
    ("fault", "message"),
    (
        ({"drop_report": 2}, "shard 2: JUnit report missing"),
        ({"skipped": 1}, "shard 1: 1 skipped"),
        ({"failures": 1}, "shard 1: 1 failures"),
        ({"errors": 1}, "shard 1: 1 errors"),
        ({"short_by": 1}, "shards ran 256 tests, collection has 257"),
    ),
)
def test_verify_rejects_lost_skipped_or_failed_tests(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    fault: dict[str, int],
    message: str,
) -> None:
    _write_shards(tmp_path, 4, **fault)
    assert shard.main(["verify", "--shards", "4", str(tmp_path)]) == 1
    assert message in capsys.readouterr().err


def test_verify_rejects_a_missing_shard(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write_shards(tmp_path, 4)
    (tmp_path / "shard-manifest-3.json").unlink()
    (tmp_path / "shard-results-3.xml").unlink()
    assert shard.main(["verify", "--shards", "4", str(tmp_path)]) == 1
    assert "are not exactly 0..3" in capsys.readouterr().err


def test_verify_rejects_an_unexpected_shard_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_shards(tmp_path, 2)
    assert shard.main(["verify", "--shards", "4", str(tmp_path)]) == 1
    assert "expected 4 shards, manifests say 2" in capsys.readouterr().err


def test_verify_rejects_disagreeing_collections(tmp_path: Path) -> None:
    _write_shards(tmp_path, 2)
    path = tmp_path / "shard-manifest-1.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["collection_sha256"] = "0" * 64
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(SystemExit, match="shards disagree about the collection"):
        shard.main(["verify", "--shards", "2", str(tmp_path)])


_SAMPLE = """\
import warnings

import pytest

warnings.warn("see pkg.mod::Thing for details", UserWarning)


@pytest.mark.parametrize("value", ["plain", "with space", "a::b", "caf\\u00e9"])
def test_param(value):
    assert value


def test_single():
    assert True
"""


def test_select_round_trips_through_a_pytest_args_file(tmp_path: Path) -> None:
    """Real collection, selection, execution and verification for two shards."""
    sample = tmp_path / "test_sample.py"
    sample.write_text(_SAMPLE, encoding="utf-8")
    reports = tmp_path / "reports"
    reports.mkdir()
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    isolate = ["-p", "no:cacheprovider"]
    ran: list[str] = []
    for index in range(2):
        args_file = tmp_path / f"args-{index}.txt"
        command = [
            sys.executable,
            str(Path(shard.__file__)),
            "select",
            "--shards=2",
            f"--index={index}",
            f"--out={args_file}",
            f"--manifest={reports / f'shard-manifest-{index}.json'}",
            *(f"--pytest-arg={argument}" for argument in isolate),
            "test_sample.py",
        ]
        subprocess.run(command, cwd=tmp_path, check=True, capture_output=True)
        selected = args_file.read_text(encoding="utf-8").splitlines()
        assert all(node.startswith("test_sample.py::") for node in selected)
        report = reports / f"shard-results-{index}.xml"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                f"@{args_file}",
                *isolate,
                f"--junitxml={report}",
            ],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )
        assert int(ET.parse(report).getroot().find("testsuite").attrib["tests"]) == len(selected)
        ran.extend(selected)
    # Five tests, each selected once; the warning text is not a node id.
    assert len(ran) == len(set(ran)) == 5
    assert shard.main(["verify", "--shards", "2", str(reports)]) == 0
