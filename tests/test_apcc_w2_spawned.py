"""Own-process W2 integration and controller-resealed adversarial replay."""

import copy
import json
import os
import threading
from pathlib import Path

import pytest

from constitutional_swarm.apcc.crypto import b64u_encode
from constitutional_swarm.apcc_empirical import w2_driver as w2


@pytest.fixture(scope="module")
def completed(tmp_path_factory):
    directory = tmp_path_factory.mktemp("w2-replay")
    original = w2.q._configuration
    keys = []

    def capture(*args, **kwargs):
        result = original(*args, **kwargs)
        keys.append(result[3])
        return result

    second_commit = threading.Event()
    original_execute = w2.B6AuthorityAdapter.execute_trusted
    original_verify = w2._verify_operation
    commits = 0
    overlap = []

    def execute(self, *args, **kwargs):
        nonlocal commits
        result = original_execute(self, *args, **kwargs)
        commits += 1
        if commits == 2:
            second_commit.set()
        return result

    def verify(row, *args, **kwargs):
        if row["index"] == 0:
            assert second_commit.wait(timeout=10), (
                "successor cannot advance during proof verification"
            )
            overlap.append(True)
        return original_verify(row, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(w2.q, "_configuration", capture)
        patch.setattr(w2.B6AuthorityAdapter, "execute_trusted", execute)
        patch.setattr(w2, "_verify_operation", verify)
        patch.chdir(directory)
        result = w2.run_smoke(Path("run"), chains=2)
    assert overlap
    values = [
        json.loads(line)
        for line in Path(result["ledger_path"]).read_bytes().splitlines()
    ]
    return directory, result, values, keys[0]


def test_two_complete_w2_chains_rotate_and_replay(completed):
    directory, result, values, _ = completed
    assert result["verified_operations"] == 200
    assert result["campaign_eligible"] is False
    assert (
        w2.verify_ledger(
            Path(result["ledger_path"]), expected_sha256=result["ledger_sha256"]
        )
        == result
    )
    assert (
        len({row["request"]["receipt"]["payload"]["agent_id"] for row in values[1:-1]})
        == 100
    )
    assert not (directory / "run" / ".authority.keys").exists()
    assert not (directory / "run" / ".controller.key").exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "profile",
        "config_digest",
        "trust",
        "producer",
        "order",
        "duplicate",
        "missing",
        "admit",
        "rotation",
        "worker",
        "bool_time",
        "source",
        "tail",
        "elapsed",
        "bool_chains",
        "float_capacity",
        "occupancy",
        "observer_pid",
        "duplicate_worker",
    ],
)
def test_resealed_semantic_mutations_fail(completed, mutation):
    directory, _, original, controller = completed
    values = copy.deepcopy(original)
    header, first, second, footer = values[0], values[1], values[2], values[-1]
    if mutation == "profile":
        header["expected_public_config"]["causal_profile"] = "default"
        header["config_sha256"] = w2._sha(w2._json(header["expected_public_config"]))
    elif mutation == "config_digest":
        header["config_sha256"] = "0" * 64
    elif mutation == "trust":
        header["trust"][0]["scope"][0] = "agent-999"
    elif mutation == "producer":
        second["request"] = copy.deepcopy(first["request"])
    elif mutation == "order":
        values[1], values[2] = values[2], values[1]
    elif mutation == "duplicate":
        values[2] = copy.deepcopy(first)
    elif mutation == "missing":
        del values[-2]
        footer["verified_operations"] -= 1
    elif mutation == "admit":
        second["admit_ns"] = first["commit_end_ns"] - 1
    elif mutation == "rotation":
        values[101]["admit_ns"] = values[100]["commit_end_ns"]
        values[101]["start_ns"] = values[100]["commit_end_ns"]
    elif mutation == "worker":
        second["worker_id"] = first["worker_id"]
        second["start_ns"] = first["start_ns"]
    elif mutation == "bool_time":
        first["admit_ns"] = False
    elif mutation == "source":
        header["provenance"]["python"] = "changed"
    elif mutation == "elapsed":
        footer["elapsed_ns"] = 0
    elif mutation == "bool_chains":
        header["chains"] = True
    elif mutation == "float_capacity":
        header["capacity"] = 16.0
    elif mutation == "occupancy":
        footer["maximum_occupancy"] = 17
    elif mutation == "duplicate_worker":
        header["worker_ids"].append(header["worker_ids"][0])
    elif mutation == "observer_pid":
        header["observer_pid"] += 1
    elif mutation == "tail":
        values.pop()
    if mutation != "tail":
        body = {key: value for key, value in footer.items() if key != "signature"}
        body["prefix_sha256"] = w2._sha(
            b"".join(w2._json(value) + b"\n" for value in values[:-1])
        )
        values[-1] = {
            **body,
            "signature": b64u_encode(controller.sign(w2._DOMAIN + w2._json(body))),
        }
    path = directory / f"tampered-{mutation}.jsonl"
    path.write_bytes(b"".join(w2._json(value) + b"\n" for value in values))
    with pytest.raises((ValueError, KeyError)):
        w2.verify_ledger(path)


def test_verification_failure_closes_workers_and_children(tmp_path, monkeypatch):
    handles = []
    child_pids = []
    authority_start = w2.start_authority
    observer_start = w2.start_authority_observer

    def authority(*args, **kwargs):
        handle = authority_start(*args, **kwargs)
        handles.append(handle)
        child_pids.append(handle.pid)
        return handle

    def observer(*args, **kwargs):
        handle = observer_start(*args, **kwargs)
        handles.append(handle)
        child_pids.append(handle.pid)
        return handle

    def fail(*args, **kwargs):
        raise RuntimeError("injected proof failure")

    monkeypatch.setattr(w2, "start_authority", authority)
    monkeypatch.setattr(w2, "start_authority_observer", observer)
    monkeypatch.setattr(w2, "_verify_operation", fail)
    with pytest.raises(
        RuntimeError, match="injected proof failure|ordered verification aborted"
    ):
        w2.run_smoke(tmp_path / "failed")
    assert not any(
        thread.name.startswith("w2-worker-") for thread in threading.enumerate()
    )
    for pid in child_pids:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    assert not (tmp_path / "failed" / ".authority.keys").exists()
    with pytest.raises(ValueError):
        w2.verify_ledger(tmp_path / "failed" / "ledger.jsonl")


@pytest.mark.parametrize("substitution", [False, True])
def test_closure_rejects_missing_or_substituted_predecessor(completed, substitution):
    _, _, values, _ = completed
    header, row = values[0], values[100]
    certificates = {}
    for previous in values[1:100]:
        response = w2.decode_signed_authority_observation(
            w2.b64u_decode(previous["observation"])
        )
        envelope = response.snapshot.certificate_envelope_bytes
        certificates[w2.decode_envelope(envelope).payload_sha256] = envelope
    last_digest = next(reversed(certificates))
    if substitution:
        certificates[last_digest] = next(iter(certificates.values()))
    else:
        del certificates[last_digest]
    launch = w2.decode_observer_launch_attestation(w2.b64u_decode(header["launch"]))
    stream = w2.AuthorityObservationVerificationStream(
        launch.session_id, next_sequence=100
    )
    with pytest.raises(ValueError, match="invalid W2 causal closure"):
        w2._verify_operation(row, header, stream, w2._trust(header), certificates)
