from __future__ import annotations

import os
from pathlib import Path

import pytest

from constitutional_swarm.apcc_empirical.artifacts import (
    ArtifactViolation,
    RawArtifactWriter,
)
from constitutional_swarm.apcc_empirical.contract import (
    derive_attack_trial,
    load_matrix,
)


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "experiments/apcc-1/matrix.v1.json"
SCHEMA_PATH = ROOT / "experiments/apcc-1/raw-result.schema.json"


def _writer(root: Path) -> RawArtifactWriter:
    matrix = load_matrix(MATRIX_PATH)
    trial = derive_attack_trial(
        matrix,
        baseline_id="B6",
        store="sqlite",
        attack_id="missing-proof",
        trial_index=0,
    )
    return RawArtifactWriter(
        root,
        "cleanup",
        matrix=matrix,
        matrix_path=MATRIX_PATH,
        schema_path=SCHEMA_PATH,
        planned_trial_ids=[trial.trial_id],
        environment={},
        environment_id="test",
        git_sha="0" * 40,
        tool_versions={"python": "test"},
    )


@pytest.mark.parametrize("exhausted_cursor", [False, True])
def test_abort_enumerates_new_files_despite_staging_directory_cursor(
    tmp_path: Path, exhausted_cursor: bool
) -> None:
    writer = _writer(tmp_path)
    staging = writer._staging_path
    assert (staging / "raw.jsonl.partial").is_file()
    if exhausted_cursor:
        # A directory descriptor may already be at the end of enumeration.
        # Linux accepts this terminal directory cookie on btrfs and tmpfs.
        os.lseek(writer._staging_fd, (1 << 63) - 1, os.SEEK_SET)
    (staging / "late-file").write_bytes(b"not published")

    writer.abort()

    assert not staging.exists()
    assert not writer.path.exists()
    assert writer._staging_fd == writer._root_fd == -1
    writer.abort()


def test_abort_refuses_symlink_even_with_exhausted_directory_cursor(
    tmp_path: Path,
) -> None:
    writer = _writer(tmp_path)
    target = tmp_path / "external"
    target.write_bytes(b"keep")
    link = writer._staging_path / "link"
    link.symlink_to(target)
    os.lseek(writer._staging_fd, (1 << 63) - 1, os.SEEK_SET)

    with pytest.raises(ArtifactViolation, match="non-regular entry"):
        writer.abort()

    assert target.read_bytes() == b"keep"
    assert link.is_symlink()
    assert not writer.path.exists()
    assert writer._staging_fd == writer._root_fd == -1
