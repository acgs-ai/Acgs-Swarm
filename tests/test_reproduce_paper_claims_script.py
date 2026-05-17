from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("torch")

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "reproduce_paper_claims.py"
_SPEC = importlib.util.spec_from_file_location("reproduce_paper_claims", _SCRIPT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)

_SYNTHETIC_SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent / "scripts" / "eval_swe_bench_synthetic.py"
)
_SYNTHETIC_SPEC = importlib.util.spec_from_file_location(
    "eval_swe_bench_synthetic", _SYNTHETIC_SCRIPT_PATH
)
assert _SYNTHETIC_SPEC is not None and _SYNTHETIC_SPEC.loader is not None
_SYNTHETIC_MODULE = importlib.util.module_from_spec(_SYNTHETIC_SPEC)
sys.modules[_SYNTHETIC_SPEC.name] = _SYNTHETIC_MODULE
_SYNTHETIC_SPEC.loader.exec_module(_SYNTHETIC_MODULE)


def _small_args(tmp_path: Path | None = None):
    parser = _MODULE.build_parser()
    argv = [
        "--seeds",
        "0",
        "--sizes",
        "10",
        "--cycles",
        "10",
        "--ablation-n",
        "5",
        "--ablation-cycles",
        "5",
        "--ablation-radii",
        "0.5,1.0",
        "--ablation-alphas",
        "0.0,0.1",
        "--ode-n",
        "5",
        "--ode-steps",
        "20",
        "--gossip-agents",
        "5",
        "--gossip-rounds",
        "4",
        "--gossip-artifacts",
        "1",
        "--gossip-partners",
        "2",
        "--swe-agents",
        "4",
        "--swe-tasks",
        "16",
        "--swe-warmup",
        "4",
        "--microbench-iterations",
        "1",
        "--microbench-n",
        "5",
    ]
    if tmp_path is not None:
        argv.extend(["--output", str(tmp_path / "claims.json")])
    return parser.parse_args(argv)


def test_reproducibility_suite_emits_claim_oriented_sections() -> None:
    payload = _MODULE.run_reproducibility_suite(_small_args())

    assert payload["pass"] is True
    assert payload["trust_variance"]["pass"] is True
    assert payload["ablation"]["pass"] is True
    assert payload["dp_calibration"]["pass"] is True
    assert payload["crdt_gossip"]["pass"] is True
    assert payload["byzantine_rejection"]["accepted_tampered"] == 0
    assert payload["synthetic_swe_bench"]["official_swe_bench_claimed"] is False
    assert payload["latency_microbenchmarks"]["ns_per_operation"]["cid_append"] > 0


def test_synthetic_swe_bench_reports_claim_anchor_fields() -> None:
    payload = _SYNTHETIC_MODULE.summarize_runs(
        seeds=[42, 7, 13],
        n_agents=4,
        n_tasks=64,
        warmup=8,
    )

    assert payload["pass"] is True
    assert payload["official_swebench_claimed"] is False
    assert payload["official_swe_bench_claimed"] is False
    assert payload["synthetic_only"] is True
    assert payload["seeds"] == [42, 7, 13]
    assert payload["task_count"] == 64
    assert payload["agent_count"] == 4
    assert payload["flat_resolve_rate"] >= 0.0
    assert payload["sinkhorn_crdt_resolve_rate"] > payload["flat_resolve_rate"]
    assert payload["fedsink_resolve_rate"] > payload["sinkhorn_crdt_resolve_rate"]
    assert payload["centralized_resolve_rate"] >= payload["fedsink_resolve_rate"]
    assert payload["flat_routing_diversity_pct"] == 0.0
    assert payload["fedsink_routing_diversity_pct"] > payload["sinkhorn_crdt_routing_diversity_pct"]
    assert payload["convergence_rounds"] <= 8


def test_synthetic_swe_bench_rejects_zero_warmup() -> None:
    with pytest.raises(ValueError, match="warmup must be at least 1"):
        _SYNTHETIC_MODULE.summarize_runs(
            seeds=[42],
            n_agents=4,
            n_tasks=16,
            warmup=0,
        )


def test_trust_variance_benchmark_keeps_birkhoff_and_residual_claims_separate() -> None:
    payload = _MODULE.trust_variance_benchmark(seeds=[0], sizes=[10], cycles=[10])
    rows = {(row["manifold"], row["n"]): row for row in payload["rows"]}

    assert rows[("birkhoff", 10)]["mean_retention"]["10"] < 0.01
    assert rows[("spectral", 10)]["mean_retention"]["10"] > 0.0
    assert rows[("spectral_residual", 10)]["mean_retention"]["10"] > 0.05


def test_cli_writes_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = _MODULE.main(
        [
            "--seeds",
            "0",
            "--sizes",
            "10",
            "--cycles",
            "10",
            "--ablation-n",
            "5",
            "--ablation-cycles",
            "5",
            "--ablation-radii",
            "0.5,1.0",
            "--ablation-alphas",
            "0.0,0.1",
            "--ode-n",
            "5",
            "--ode-steps",
            "20",
            "--gossip-agents",
            "5",
            "--gossip-rounds",
            "4",
            "--gossip-artifacts",
            "1",
            "--gossip-partners",
            "2",
            "--swe-agents",
            "4",
            "--swe-tasks",
            "16",
            "--swe-warmup",
            "4",
            "--microbench-iterations",
            "1",
            "--microbench-n",
            "5",
            "--output",
            str(tmp_path / "claims.json"),
        ]
    )

    stdout_payload = json.loads(capsys.readouterr().out)
    file_payload = json.loads((tmp_path / "claims.json").read_text(encoding="utf-8"))
    assert code == 0
    assert stdout_payload == file_payload
    assert file_payload["pass"] is True
