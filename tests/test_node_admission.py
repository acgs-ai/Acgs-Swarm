"""Tests for abliteration-aware quorum node admission.

Deterministic, numpy-only: build clean residual-stream write matrices, apply the
exact Heretic/Arditi edit to forge an "abliterated" candidate, and confirm the
admission gate keeps it out of the selected committee.
"""

from __future__ import annotations

import numpy as np
import pytest

from constitutional_swarm.eval.monotonic_mas import abliteration_detector as ad
from constitutional_swarm.node_admission import (
    AbliterationAdmissionGate,
    AdmissionDecision,
)
from constitutional_swarm.validator_set import (
    CommitteeSelector,
    ValidatorIdentity,
    ValidatorSet,
)

D_MODEL = 64
D_IN = 48
N_LAYERS = 4


def _rng() -> np.random.Generator:
    return np.random.default_rng(0)


def _clean_model(rng: np.random.Generator) -> dict[str, np.ndarray]:
    return {f"layer{i}.W_out": rng.standard_normal((D_MODEL, D_IN)) for i in range(N_LAYERS)}


def _abliterate(model: dict[str, np.ndarray], r: np.ndarray, layers) -> dict[str, np.ndarray]:
    out = dict(model)
    for i in layers:
        out[f"layer{i}.W_out"] = ad.apply_abliteration(model[f"layer{i}.W_out"], r)
    return out


def _fixture():
    rng = _rng()
    reference = _clean_model(rng)
    r = ad.refusal_direction(
        rng.standard_normal((32, D_MODEL)) + 4.0, rng.standard_normal((32, D_MODEL))
    )
    clean = _clean_model(rng)
    fully = _abliterate(clean, r, range(N_LAYERS))
    minority = _abliterate(clean, r, [0])  # only 1/4 -> median would miss, min catches
    return reference, r, clean, fully, minority


# --- screening -------------------------------------------------------------


def test_screen_admits_clean_rejects_abliterated() -> None:
    reference, r, clean, fully, _ = _fixture()
    gate = AbliterationAdmissionGate(r, reference=reference)
    decision = gate.screen({"clean": clean, "tampered": fully})
    assert isinstance(decision, AdmissionDecision)
    assert decision.admitted == ("clean",)
    assert decision.rejected == ("tampered",)
    assert decision.reports["tampered"].abliterated is True
    assert decision.reports["clean"].abliterated is False


def test_min_preset_catches_minority_subset() -> None:
    # The whole point of wiring the "min" preset: a single ablated layer (1/4)
    # that the median default would miss must still be rejected.
    reference, r, clean, _, minority = _fixture()
    assert AbliterationAdmissionGate(r, reference=reference, aggregate="median").screen(
        {"x": minority}
    ).reports["x"].abliterated is False
    gate = AbliterationAdmissionGate(r, reference=reference)  # default = "min"
    assert gate.screen({"x": minority}).rejected == ("x",)


def test_no_reference_uses_absolute_floor() -> None:
    reference, r, clean, fully, _ = _fixture()
    gate = AbliterationAdmissionGate(r)  # no reference -> abs-floor + min
    decision = gate.screen({"clean": clean, "tampered": fully})
    assert decision.admitted == ("clean",)
    assert decision.rejected == ("tampered",)


def test_rejected_set_is_frozenset() -> None:
    reference, r, clean, fully, _ = _fixture()
    gate = AbliterationAdmissionGate(r, reference=reference)
    decision = gate.screen({"a": fully, "b": clean})
    assert decision.rejected_set == frozenset({"a"})


# --- committee selection wiring -------------------------------------------


def _validator_set(ids) -> ValidatorSet:
    return ValidatorSet(
        ValidatorIdentity(agent_id=i, stake=1.0, fault_domain=f"org:{i}") for i in ids
    )


def test_select_admissible_excludes_abliterated_node() -> None:
    reference, r, clean, fully, _ = _fixture()
    vset = _validator_set(["a", "b", "c", "d"])
    selector = CommitteeSelector(vset)
    gate = AbliterationAdmissionGate(r, reference=reference)

    # "c" is abliterated; the rest are clean.
    candidates = {"a": clean, "b": clean, "c": fully, "d": clean}
    selection, decision = gate.select_admissible(selector, seed="case-1", committee_size=4, candidate_write_matrices=candidates)

    assert "c" in decision.rejected
    assert "c" not in selection.members
    assert set(selection.members) == {"a", "b", "d"}


def test_select_admissible_unions_explicit_exclude() -> None:
    reference, r, clean, fully, _ = _fixture()
    vset = _validator_set(["a", "b", "c", "d"])
    selector = CommitteeSelector(vset)
    gate = AbliterationAdmissionGate(r, reference=reference)
    candidates = {"a": clean, "b": fully, "c": clean, "d": clean}

    # Producer "a" is excluded (MACI) AND "b" is abliterated.
    selection, decision = gate.select_admissible(
        selector, seed="case-2", committee_size=4, candidate_write_matrices=candidates, exclude=["a"]
    )
    assert "a" not in selection.members  # explicit exclude honored
    assert "b" not in selection.members  # abliteration exclude honored
    assert set(selection.members) == {"c", "d"}


def test_select_admissible_all_clean_is_full_committee() -> None:
    reference, r, clean, _, _ = _fixture()
    vset = _validator_set(["a", "b", "c"])
    selector = CommitteeSelector(vset)
    gate = AbliterationAdmissionGate(r, reference=reference)
    candidates = {i: clean for i in ["a", "b", "c"]}
    selection, decision = gate.select_admissible(selector, seed="s", committee_size=3, candidate_write_matrices=candidates)
    assert decision.rejected == ()
    assert set(selection.members) == {"a", "b", "c"}


def test_select_admissible_require_independent_path() -> None:
    reference, r, clean, fully, _ = _fixture()
    vset = _validator_set(["a", "b", "c", "d", "e"])
    selector = CommitteeSelector(vset)
    gate = AbliterationAdmissionGate(r, reference=reference)
    candidates = {i: clean for i in ["a", "b", "c", "d"]}
    candidates["e"] = fully
    selection, decision = gate.select_admissible(
        selector, seed="ind", committee_size=4, candidate_write_matrices=candidates,
        require_independent=True,
    )
    assert "e" not in selection.members
    assert selection.has_quorum()


def test_gate_copies_direction() -> None:
    # Mutating the caller's direction array after construction must not change verdicts.
    reference, r, clean, fully, _ = _fixture()
    r = r.copy()
    gate = AbliterationAdmissionGate(r, reference=reference)
    r[:] = 0.0  # caller scribbles over their array
    decision = gate.screen({"tampered": fully})
    assert decision.rejected == ("tampered",)


def test_malformed_candidate_propagates_valueerror() -> None:
    reference, r, *_ = _fixture()
    gate = AbliterationAdmissionGate(r, reference=reference)
    with pytest.raises(ValueError, match="empty"):
        gate.screen({"bad": {}})
