import pytest

from offline_foundations.demo import generate


def test_local_demo_is_reproducible_and_refuses_existing_output(tmp_path):
    path = tmp_path / "new-fixture"
    result = generate(path)
    assert result["model_calls_executed"] == 0
    assert result["decision"]["consumer"]["status"] == "available_recorded_fixture"
    assert result["consume_after_revocation"]["status"] == "abstain"
    assert result["prompt_counts"]["task_executions"] == 220
    assert result["prompt_counts"]["incomplete_reservations"] == 0
    assert result["final_status"] == "recorded_matrix_complete_not_model_quality"
    assert result["promotion"] == "not_evaluated"
    with pytest.raises(FileExistsError):
        generate(path)
