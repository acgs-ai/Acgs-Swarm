"""C21 regression tests: admission gates and the monotonic-MAS evaluator.

Each test feeds an invalid or hostile input and expects rejection:

- admission-2: a caller mutating the trusted reference after constructing the
  gate must not change its verdict.
- bench-eval-1: a candidate whose matrix names differ from the reference set
  (renamed or extra matrices) must be flagged, not silently scored on a subset.
- bench-eval-9: an R4 import-graph audit that cannot run must fail the
  iteration, must not leak ``sys.path`` entries, and must run every iteration.
- opt-3: the three gates share one screen-and-select implementation.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

import numpy as np
import pytest

from constitutional_swarm.eval.monotonic_mas import abliteration_detector as ad
from constitutional_swarm.eval.monotonic_mas import evaluator
from constitutional_swarm.eval.monotonic_mas.replay import DEFAULT_DETECTORS
from constitutional_swarm.node_admission import (
    AbliterationAdmissionGate,
    ActivationAdmissionGate,
    RefusalDistributionGate,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
REAL_CORPUS = REPO_ROOT / "tests" / "fixtures" / "mast_synth_v1.jsonl"

D_MODEL = 32
D_IN = 24
N_LAYERS = 4


def _weights_fixture():
    rng = np.random.default_rng(21)
    reference = {
        f"layer{i}.W_out": rng.standard_normal((D_MODEL, D_IN)) for i in range(N_LAYERS)
    }
    direction = ad.refusal_direction(
        rng.standard_normal((32, D_MODEL)) + 4.0, rng.standard_normal((32, D_MODEL))
    )
    clean = {
        name: rng.standard_normal((D_MODEL, D_IN)) for name in reference
    }
    return reference, direction, clean


# --------------------------------------------------------------------------
# admission-2: reference is snapshotted at construction
# --------------------------------------------------------------------------


def test_reference_array_mutation_after_construction_does_not_change_verdict() -> None:
    reference, direction, clean = _weights_fixture()
    gate = AbliterationAdmissionGate(direction, reference=reference)
    assert gate.evaluate(clean).abliterated is False

    # Concentrate every reference matrix on the refusal direction (in place) so
    # the clean candidate's energy ratio would collapse against it.
    for name in reference:
        reference[name] += 1e3 * np.outer(direction, np.ones(D_IN))

    assert gate.evaluate(clean).abliterated is False


def test_reference_mapping_mutation_after_construction_does_not_change_verdict() -> None:
    reference, direction, clean = _weights_fixture()
    gate = AbliterationAdmissionGate(direction, reference=reference)

    reference["layer99.W_out"] = np.ones((D_MODEL, D_IN))

    report = gate.evaluate(clean)
    assert report.abliterated is False
    assert report.reasons == []


def test_gate_reference_snapshot_is_read_only() -> None:
    reference, direction, _ = _weights_fixture()
    gate = AbliterationAdmissionGate(direction, reference=reference)
    snapshot = gate._reference
    assert snapshot is not None
    with pytest.raises(TypeError):
        snapshot["layer0.W_out"] = np.zeros((D_MODEL, D_IN))  # type: ignore[index]
    with pytest.raises(ValueError):
        snapshot["layer0.W_out"][0, 0] = 1.0


def test_empty_reference_is_rejected_at_construction() -> None:
    _, direction, _ = _weights_fixture()
    with pytest.raises(ValueError, match="reference"):
        AbliterationAdmissionGate(direction, reference={})


# --------------------------------------------------------------------------
# bench-eval-1: candidate matrix names must equal the reference names
# --------------------------------------------------------------------------


@pytest.mark.parametrize("aggregate", ["median", "mean", "min", "quantile"])
def test_unknown_candidate_matrix_names_are_flagged(aggregate: str) -> None:
    reference, direction, clean = _weights_fixture()
    candidate = dict(clean)
    candidate["renamed.W_out"] = ad.apply_abliteration(clean["layer0.W_out"], direction)

    report = ad.detect_from_weights(
        candidate, direction, reference=reference, aggregate=aggregate
    )

    assert report.abliterated is True
    assert any("unknown" in reason and "renamed.W_out" in reason for reason in report.reasons)


def test_renamed_abliterated_matrices_with_one_clean_match_are_flagged() -> None:
    """Finding repro: {L0 clean, renamed L1..L3 abliterated} must not pass."""
    reference, direction, clean = _weights_fixture()
    candidate = {"layer0.W_out": clean["layer0.W_out"]}
    for i in range(1, N_LAYERS):
        candidate[f"renamed_L{i}"] = ad.apply_abliteration(clean[f"layer{i}.W_out"], direction)

    report = ad.detect_from_weights(candidate, direction, reference=reference, aggregate="min")

    assert report.abliterated is True


def test_gate_rejects_candidate_with_extra_matrix() -> None:
    reference, direction, clean = _weights_fixture()
    gate = AbliterationAdmissionGate(direction, reference=reference)
    candidate = {**clean, "extra.W_out": clean["layer0.W_out"]}

    decision = gate.screen({"n0": clean, "n1": candidate})

    assert decision.admitted == ("n0",)
    assert decision.rejected == ("n1",)


def test_exact_reference_names_still_admit_clean_candidate() -> None:
    reference, direction, clean = _weights_fixture()
    report = ad.detect_from_weights(clean, direction, reference=reference, aggregate="min")
    assert report.abliterated is False


# --------------------------------------------------------------------------
# bench-eval-9: R4 import-graph audit is gated and side-effect free
# --------------------------------------------------------------------------


def test_import_graph_audit_does_not_mutate_sys_path() -> None:
    before = list(sys.path)
    result = evaluator.import_graph_audit()
    assert result["audited"] is True
    assert sys.path == before


def test_import_graph_audit_reports_missing_generator(tmp_path: Path) -> None:
    result = evaluator.import_graph_audit(tmp_path / "missing_generator.py")
    assert result["audited"] is False


def test_import_graph_audit_detects_multi_name_import(tmp_path: Path) -> None:
    generator = tmp_path / "gen.py"
    generator.write_text("import json, constitutional_swarm\n")
    with pytest.raises(RuntimeError, match="R4 violation"):
        evaluator.import_graph_audit(generator)


def test_import_graph_audit_detects_nested_import(tmp_path: Path) -> None:
    generator = tmp_path / "gen.py"
    generator.write_text(
        "def build():\n    from constitutional_swarm.mesh import ConstitutionalMesh\n"
    )
    with pytest.raises(RuntimeError, match="R4 violation"):
        evaluator.import_graph_audit(generator)


@pytest.mark.parametrize(
    "source",
    [
        "import importlib\nm = importlib.import_module('constitutional_' + 'swarm')\n",
        "from importlib import import_module\nm = import_module('constitutional_' + 'swarm')\n",
        "import importlib.util as u\n",
        "m = __import__('constitutional_' + 'swarm')\n",
        "exec('import constitutional_' + 'swarm')\n",
        "x = eval('1')\n",
        "code = compile('import os', '<x>', 'exec')\n",
        "f = exec\n",
        "import builtins\nm = builtins.__import__('constitutional_' + 'swarm')\n",
        "import sys\nm = sys.modules.get('constitutional_' + 'swarm')\n",
        "b = __builtins__\n",
        "s = ().__class__.__base__.__subclasses__()\n",
    ],
    ids=[
        "importlib.import_module",
        "from-importlib",
        "importlib-submodule",
        "__import__",
        "exec-call",
        "eval-call",
        "compile-call",
        "exec-alias",
        "builtins.__import__",
        "sys.modules",
        "__builtins__",
        "dunder-escape",
    ],
)
def test_import_graph_audit_fails_closed_on_dynamic_import(
    tmp_path: Path, source: str
) -> None:
    generator = tmp_path / "gen.py"
    generator.write_text(source)

    result = evaluator.import_graph_audit(generator)

    assert result["audited"] is False
    assert result["reason"]


def test_import_graph_audit_does_not_execute_rejected_generator(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    generator = tmp_path / "gen.py"
    generator.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('x')\n"
        "m = __import__('constitutional_' + 'swarm')\n"
    )

    assert evaluator.import_graph_audit(generator)["audited"] is False
    assert not marker.exists()


def test_import_graph_audit_executes_the_bytes_it_parsed(tmp_path: Path, monkeypatch) -> None:
    """TOCTOU: the source is read once; a swap after parsing cannot run."""
    generator = tmp_path / "gen.py"
    generator.write_text("VALUE = 1\n")
    reads: list[Path] = []
    original_read_bytes = Path.read_bytes
    original_read_text = Path.read_text

    def counting_read_bytes(self: Path) -> bytes:
        reads.append(self)
        data = original_read_bytes(self)
        self.write_text("m = __import__('constitutional_' + 'swarm')\n")
        return data

    def counting_read_text(self: Path, *args, **kwargs) -> str:
        reads.append(self)
        data = original_read_text(self, *args, **kwargs)
        self.write_text("m = __import__('constitutional_' + 'swarm')\n")
        return data

    monkeypatch.setattr(Path, "read_bytes", counting_read_bytes)
    monkeypatch.setattr(Path, "read_text", counting_read_text)
    monkeypatch.setattr(
        "importlib.util.spec_from_file_location",
        lambda *a, **k: pytest.fail("generator must not be re-read via a loader"),
    )

    result = evaluator.import_graph_audit(generator)

    assert result["audited"] is True
    assert reads == [generator]


@pytest.mark.parametrize("statement", ["raise SystemExit(0)", "exit(0)"])
def test_import_graph_audit_system_exit_is_not_fail_open(
    tmp_path: Path, statement: str
) -> None:
    generator = tmp_path / "gen.py"
    generator.write_text(statement + "\n")

    result = evaluator.import_graph_audit(generator)

    assert result["audited"] is False


def test_real_generator_passes_audit() -> None:
    assert evaluator.import_graph_audit() == {"audited": True, "leaked": []}


# Round-2 probes (security delta review): each bypassed the round-1 denylist.
_R4_PROBES = {
    "from_os_import_sys": "from os import sys as s\nm = s.modules['constitutional_' + 'swarm']\n",
    "attrgetter_os_sys": (
        "import os\nfrom operator import attrgetter as a\n"
        "m = a('sys')(os).modules['constitutional_' + 'swarm']\n"
    ),
    "attrgetter_import": (
        "import os\nfrom operator import attrgetter as a\n"
        "m = a('sys')(os).modules['importlib'].import_module('constitutional_'+'swarm')\n"
    ),
    "pickle_import": (
        "import pickle\n"
        "m = pickle.loads(b'cbuiltins\\n__import__\\n(Vconstitutional_swarm\\ntR.')\n"
    ),
    "match_kwd_dunder": "match ():\n    case object(__class__=c):\n        pass\nm = c\n",
    "subprocess": "import subprocess\nm = subprocess.run(['true']).returncode\n",
    "tamper_evaluator": (
        "from os import sys as s\n"
        "ev = s.modules['constitutional_swarm.eval.monotonic_mas.evaluator']\n"
        "ev.EXPECTED_HASH = 'pwned'\nm = ev.EXPECTED_HASH\n"
    ),
    # One-hop module escapes through allowlisted stdlib modules.
    "argparse_private_sys": "import argparse\nm = argparse._sys.modules\n",
    "json_submodule": "import json\nm = json.decoder\n",
    "from_allowed_import_module": "from json import decoder\nm = decoder\n",
    "match_kwd_private": "import argparse\nmatch argparse:\n    case object(_sys=s):\n        pass\nm = s\n",
}
_MARKER = "from pathlib import Path as _P\n_P({marker!r}).write_text(repr(m)[:80])\n"


@pytest.mark.parametrize("name", sorted(_R4_PROBES))
def test_r4_probe_is_rejected_without_execution(tmp_path: Path, name: str) -> None:
    marker = tmp_path / f"{name}.out"
    generator = tmp_path / f"{name}.py"
    generator.write_text(_R4_PROBES[name] + _MARKER.format(marker=str(marker)))

    result = evaluator.import_graph_audit(generator)

    assert result["audited"] is False
    assert not marker.exists(), "rejected generator must never execute"
    assert evaluator.EXPECTED_HASH == "608508a9bd224290"


def test_generator_execution_cannot_mutate_evaluator_state(tmp_path: Path) -> None:
    """Even a generator that reaches the dynamic stage runs out of process."""
    marker = tmp_path / "ran"
    source = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('child')\n"
        "import constitutional_swarm.eval.monotonic_mas.evaluator as ev\n"
        "ev.EXPECTED_HASH = 'pwned'\n"
    ).encode()
    modules_before = set(sys.modules)

    report = evaluator._execute_generator_isolated(source, tmp_path / "gen.py")

    assert marker.read_text() == "child"  # it really ran, in the child
    assert evaluator.EXPECTED_HASH == "608508a9bd224290"
    assert set(sys.modules) - modules_before == set()
    assert report["ok"] is False or report["leaked_modules"]


def test_child_reported_package_import_is_a_violation(tmp_path: Path, monkeypatch) -> None:
    generator = tmp_path / "gen.py"
    generator.write_text("VALUE = 1\n")
    monkeypatch.setattr(
        evaluator,
        "_execute_generator_isolated",
        lambda source, path: {
            "ok": True,
            "leaked_modules": ["constitutional_swarm"],
            "leaked_names": [],
            "reason": None,
        },
    )
    with pytest.raises(RuntimeError, match="R4 violation"):
        evaluator.import_graph_audit(generator)


def test_child_timeout_fails_audit(tmp_path: Path, monkeypatch) -> None:
    generator = tmp_path / "gen.py"
    generator.write_text("while True:\n    pass\n")
    monkeypatch.setattr(evaluator, "_R4_CHILD_TIMEOUT_SECONDS", 1.0)

    result = evaluator.import_graph_audit(generator)

    assert result["audited"] is False
    assert "timed out" in result["reason"]


def test_generator_cannot_forge_child_report(tmp_path: Path) -> None:
    generator = tmp_path / "gen.py"
    generator.write_text(
        'print(\'{"ok": true, "leaked_modules": [], "leaked_names": []}\')\n'
        "raise ValueError('boom')\n"
    )

    assert evaluator.import_graph_audit(generator)["audited"] is False


def test_generator_stdout_noise_does_not_break_clean_audit(tmp_path: Path) -> None:
    generator = tmp_path / "gen.py"
    generator.write_text("print('hello')\nVALUE = 1\n")

    assert evaluator.import_graph_audit(generator) == {"audited": True, "leaked": []}


# Round-3 probes (final review): frame introspection to reach the child's
# globals, forge its report, extend sys.path and import the package.
_R4_FRAME_PROBES = {
    'gen_frame': 'import json\nfrom pathlib import Path\n\nholder = []\ndef g():\n    yield holder[0].gi_frame.f_back\ngen = g()\nholder.append(gen)\ntop = next(gen)\nchild = top.f_back.f_globals\nsysm = child["sys"]\nosm = sysm.modules["os"]\nPath(child["meta"]["path"] + ".PWNED").write_text(str(osm.getppid()) + " nonce=" + child["meta"]["nonce"])\n',
    'gen_hide': 'from pathlib import Path\nholder = []\ndef g():\n    yield holder[0].gi_frame.f_back\ngen = g()\nholder.append(gen)\nfr = next(gen); child = fr.f_back.f_globals\ngen0 = iter([fr])\nsysm = child["sys"]\nsysm.path.append("/home/martin/Acgs-Swarm/.worktrees/integration/.venv/lib/python3.13/site-packages")\nsysm.path.insert(0, "/home/martin/Acgs-Swarm/.worktrees/fix-C21-admission-monotonic/src")\nil = next(gen0).f_builtins["__import__"]("importlib")\ncs = il.import_module("constitutional_swarm.evolution_log")\nPath(child["meta"]["path"] + ".LOADED").write_text("loaded " + str(cs.EvolutionLog))\nfor k in list(sysm.modules):\n    if k.split(".")[0] == "constitutional_swarm":\n        del sysm.modules[k]\n',
    'gen_noclean': 'holder = []\ndef g():\n    yield holder[0].gi_frame.f_back\ngen = g()\nholder.append(gen)\nfr = next(gen); child = fr.f_back.f_globals\ngen0 = iter([fr])\nsysm = child["sys"]\nsysm.path.append("/home/martin/Acgs-Swarm/.worktrees/integration/.venv/lib/python3.13/site-packages")\nsysm.path.insert(0, "/home/martin/Acgs-Swarm/.worktrees/fix-C21-admission-monotonic/src")\nnext(gen0).f_builtins["__import__"]("constitutional_swarm.evolution_log")\n',
}


@pytest.mark.parametrize("name", sorted(_R4_FRAME_PROBES))
def test_r4_frame_introspection_probe_is_rejected(tmp_path: Path, name: str) -> None:
    generator = tmp_path / f"{name}.py"
    generator.write_text(_R4_FRAME_PROBES[name])

    result = evaluator.import_graph_audit(generator)

    assert result["audited"] is False
    for suffix in (".PWNED", ".LOADED"):
        assert not Path(str(generator) + suffix).exists(), "probe must not execute"


@pytest.mark.parametrize(
    "source",
    [
        "def g():\n    yield 1\nx = g().gi_frame\n",
        "def f():\n    return f.co_consts\n",
        "x = [].f_back\n",
        "d = {}\nx = d['f_globals']\n",
        "import json\nx = json.loads('{}').get('co_code')\n",
        "def h(*a):\n    return a\nx = h(1, 'tb_frame')\n",
        "match 1:\n    case object(f_back=b):\n        pass\n",
    ],
    ids=[
        "gi_frame-attr",
        "co_-attr",
        "f_back-attr",
        "subscript-key",
        "call-key",
        "call-arg",
        "match-kwd",
    ],
)
def test_static_check_rejects_introspection(source: str) -> None:
    import ast

    assert evaluator._r4_static_findings(ast.parse(source))


@pytest.mark.parametrize(
    "source",
    [
        "m = __import__('constitutional_' + 'swarm')\n",
        (
            f"import sys\nsys.path.insert(0, {str(REPO_ROOT / 'src')!r})\n"
            "import importlib\nimportlib.import_module('constitutional_swarm.evolution_log')\n"
        ),
        (
            # Hide the evidence: restore sys.path and purge sys.modules after
            # loading. Only the exec audit hook can see this one.
            f"import sys\nsaved = list(sys.path)\nsys.path.insert(0, {str(REPO_ROOT / 'src')!r})\n"
            "import importlib\nimportlib.import_module('constitutional_swarm.evolution_log')\n"
            "sys.path[:] = saved\n"
            "for k in [k for k in sys.modules if k.startswith('constitutional_swarm')]:\n"
            "    del sys.modules[k]\n"
        ),
        "import site\n",
        "import ensurepip\n",
        "import sys\nsys.path.append('/nonexistent-c21')\n",
        "import sys\nsys.path[:] = []\n",
    ],
    ids=[
        "__import__",
        "importlib",
        "importlib-hidden",
        "site",
        "ensurepip",
        "path-append",
        "path-clear",
    ],
)
def test_child_audit_hook_detects_violation_without_self_report(
    tmp_path: Path, source: str
) -> None:
    """Bypass the static stage: the child's audit hook alone must catch these."""
    report = evaluator._execute_generator_isolated(source.encode(), tmp_path / "gen.py")

    assert report["ok"] is False
    assert report["violation"] is True


def test_child_violation_exit_is_an_r4_violation(tmp_path: Path, monkeypatch) -> None:
    generator = tmp_path / "gen.py"
    generator.write_text("m = __import__('constitutional_' + 'swarm')\n")
    monkeypatch.setattr(evaluator, "_r4_static_findings", lambda tree: [])
    monkeypatch.setattr(evaluator, "_static_package_imports", lambda tree: [])

    with pytest.raises(RuntimeError, match="R4 violation"):
        evaluator.import_graph_audit(generator)


def _available_role(trace: dict, governance_enabled: bool) -> tuple[bool, dict]:
    caught = governance_enabled and trace["payload"] != "hello world"
    return caught, {
        "status": "available",
        "semantic_status": "available",
        "semantic_unavailable_reason": None,
    }


def _run_iteration(iter_n: int, run_id: str, mission_root: Path) -> dict:
    args = argparse.Namespace(
        iter_n=iter_n,
        run_id=run_id,
        corpus=str(REAL_CORPUS),
        mission_root=str(mission_root),
    )
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        evaluator._execute_iteration(
            args,
            detectors={**DEFAULT_DETECTORS, "role_drift": _available_role},
            evaluation_variant="test-c21-r4-v1",
        )
    return json.loads(stdout.getvalue())


def test_unauditable_generator_fails_iteration(tmp_path: Path, monkeypatch) -> None:
    mission_root = tmp_path / "mission"
    assert _run_iteration(0, "r4-unavailable", mission_root)["pass"] is True

    monkeypatch.setattr(
        evaluator, "_R4_GENERATOR_PATH", tmp_path / "no_such_generator.py"
    )
    iter1 = _run_iteration(1, "r4-unavailable", mission_root)

    assert iter1["audit_R4"]["audited"] is False
    assert iter1["gates"]["r4_import_graph_audited"] is False
    assert iter1["pass"] is False


def test_audit_runs_and_is_gated_on_every_iteration(tmp_path: Path) -> None:
    mission_root = tmp_path / "mission"
    _run_iteration(0, "r4-every-iter", mission_root)
    iter1 = _run_iteration(1, "r4-every-iter", mission_root)
    iter2 = _run_iteration(2, "r4-every-iter", mission_root)

    for result in (iter1, iter2):
        assert result["audit_R4"]["audited"] is True
        assert result["gates"]["r4_import_graph_audited"] is True
    assert iter1["pass"] is True


def test_persisted_result_without_r4_gate_is_rejected(tmp_path: Path) -> None:
    mission_root = tmp_path / "mission"
    _run_iteration(0, "r4-persisted", mission_root)
    _run_iteration(1, "r4-persisted", mission_root)
    result_path = mission_root / "runs" / "r4-persisted" / "evaluations" / "iteration-0001.json"
    stored = json.loads(result_path.read_text())
    stored["gates"].pop("r4_import_graph_audited")
    # Re-seal the digest so only the missing gate can cause the rejection.
    stored["result_digest"] = evaluator._result_digest(stored)
    result_path.write_text(json.dumps(stored))

    with pytest.raises(ValueError, match="r4_import_graph_audited"):
        evaluator._validate_result(
            result_path,
            expected_iter=1,
            expected_request_digest=stored["request_digest"],
        )


# --------------------------------------------------------------------------
# opt-3: one shared screen-and-select implementation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "gate_cls", [AbliterationAdmissionGate, ActivationAdmissionGate, RefusalDistributionGate]
)
def test_gates_share_screen_and_select(gate_cls: type) -> None:
    from constitutional_swarm.node_admission import _GateBase

    assert issubclass(gate_cls, _GateBase)
    assert "_screen_and_select" not in vars(gate_cls)
