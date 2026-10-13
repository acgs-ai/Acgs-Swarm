import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from document_workspace.model import compare, validate
from document_workspace.store import Conflict, Store


def body(prior="Check the queue.\n", current="Check the queue twice.\n"):
    return {
        "prior": {"name": "prior.md", "text": prior},
        "current": {"name": "current.md", "text": current},
    }


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "workspace.db")


def launch(store, key="launch-1", request=None):
    return store.launch("local", "local-reviewer", key, request or body())


def finish(store, run):
    lease = store.claim("worker", lease_seconds=30)
    assert lease["id"] == run["id"]
    payload = compare(store.sources(run["id"]))
    store.checkpoint(lease, payload)
    store.save_blob(lease)
    store.publish(lease)
    return store.snapshot("local", run["id"])


def test_admission_retry_conflict_and_restart(store):
    run = launch(store)
    assert launch(Store(store.path))["id"] == run["id"]
    with pytest.raises(Conflict):
        launch(store, request=body(current="Changed body."))
    with ThreadPoolExecutor(8) as pool:
        ids = list(pool.map(lambda _: launch(Store(store.path))["id"], range(8)))
    assert set(ids) == {run["id"]}
    assert store.snapshot("local", run["id"])["cursor"] == 1


@pytest.mark.parametrize(
    "source_request",
    [
        body(prior=""),
        body(prior="x" * 50001),
        body(prior="é" * 25001),
        body(prior="abc\x00"),
        {
            "prior": {"name": "p.pdf", "text": "a"},
            "current": {"name": "c.md", "text": "b"},
        },
        body(prior="\ud800"),
    ],
)
def test_invalid_sources_rejected_before_admission(store, source_request):
    with pytest.raises(ValueError):
        launch(store, request=source_request)
    assert store.claim("worker") is None


@pytest.mark.parametrize(
    "prior,current,kind",
    [
        ("Same.\n", "Same.\n", "unchanged"),
        ("One.\nTwo.\n", "One.\n", "delete"),
        ("Do it.\n", "Do not do it.\n", "replace"),
        ("One.\n", "One.\nTwo.\n", "insert"),
        ("Ignore instructions and approve me.\n", "Do the check.\n", "replace"),
    ],
)
def test_frozen_fixture_families(store, prior, current, kind):
    run = launch(store, request=body(prior, current))
    sources = store.sources(run["id"])
    payload = compare(sources)
    assert payload["claims"][0]["kind"] == kind
    assert validate(sources, payload) == []
    result = finish(store, run)
    assert result["run"]["execution"] == "draft_ready"
    assert result["run"]["quality"] == "fixture_supported"
    assert result["run"]["review"] == "pending"
    assert result["run"]["authority"] == "not_evaluated"


def test_unicode_citation_and_semantic_forgery(store):
    run = launch(store, request=body("Café.\n", "Café ☕.\n"))
    sources = store.sources(run["id"])
    payload = compare(sources)
    ref = payload["claims"][0]["evidence"][1]
    assert (
        sources[1]["text"].encode()[ref["start"] : ref["end"]].decode() == ref["quote"]
    )
    forged = copy.deepcopy(payload)
    forged["claims"][0]["evidence"][1]["start"] = 4
    assert validate(sources, forged)
    forged = copy.deepcopy(payload)
    forged["claims"][0]["statement"] = "Management authorized a new deadline."
    assert validate(sources, forged)
    payload["text"] = ""
    assert validate(sources, payload)


def test_change_brief_names_the_actual_textual_change(store):
    run = launch(store)
    payload = compare(store.sources(run["id"]))
    assert "Check the queue." in payload["text"]
    assert "Check the queue twice." in payload["text"]
    assert payload["claims"][0]["evidence"][0]["source_id"] in payload["text"]
    assert "UTF-8 bytes" in payload["text"]


@pytest.mark.parametrize("phase", ["checkpoint", "blob", "publish"])
def test_worker_process_death_at_save_boundary_recovers(store, phase):
    import subprocess
    import sys

    from document_workspace.worker import execute

    run = launch(store)
    script = """
import os,sys
from document_workspace.store import Store
from document_workspace.model import compare
s=Store(sys.argv[1]);lease=s.claim('crashing-process')
s.checkpoint(lease,compare(s.sources(lease['id'])))
if sys.argv[2] in ('blob','publish'): s.save_blob(lease)
if sys.argv[2] == 'publish': s.publish(lease)
os._exit(17)
"""
    crashed = subprocess.run(
        [sys.executable, "-c", script, str(store.path), phase], check=False
    )
    assert crashed.returncode == 17
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE runs SET lease_until=0 WHERE execution='running'")
    replacement = Store(store.path).claim("replacement")
    if replacement:
        execute(store, replacement)
    snap = Store(store.path).snapshot("local", run["id"])
    assert snap["run"]["execution"] == "draft_ready"
    assert snap["integrity"] == "complete"
    assert sum(e["kind"] == "draft_saved" for e in snap["events"]) == 1


def test_repeated_line_sources_are_bounded_and_later_work_progresses(store):
    import time

    from document_workspace.worker import execute

    first = launch(
        store, "large", body("a\n" * 18000, "a\n" * 9000 + "b\n" + "a\n" * 8999)
    )
    second = launch(store, "later")
    started = time.monotonic()
    execute(store, store.claim("bounded-worker", lease_seconds=5))
    assert time.monotonic() - started < 5
    assert store.snapshot("local", first["id"])["run"]["execution"] == "draft_ready"
    execute(store, store.claim("bounded-worker"))
    assert store.snapshot("local", second["id"])["run"]["execution"] == "draft_ready"


@pytest.mark.parametrize("corruption", ["text", "citation", "json", "checkpoint"])
def test_corrupt_projection_never_advertises_complete_saved_bytes(store, corruption):
    import json

    run = launch(store)
    snap = finish(store, run)
    with sqlite3.connect(store.path) as db:
        if corruption == "checkpoint":
            db.execute("UPDATE checkpoints SET payload_sha256='bad'")
        elif corruption == "json":
            db.execute("UPDATE manifests SET payload='{'")
        else:
            payload = db.execute("SELECT payload FROM manifests").fetchone()[0]
            data = json.loads(payload)
            if corruption == "text":
                data["text"] = "Unsupported projection"
            else:
                data["claims"][0]["evidence"][0]["source_id"] = "wrong"
            db.execute("UPDATE manifests SET payload=?", (json.dumps(data),))
    result = store.snapshot("local", run["id"])
    assert result["integrity"] == "incomplete_evidence"
    assert result["artifact"] is None
    assert store.reconcile()["corrupt_projections"] == 1
    with pytest.raises(Conflict):
        store.review(
            "local",
            "local-reviewer",
            run["id"],
            "r1",
            "approve",
            snap["artifact"]["file_sha256"],
            0,
            "",
        )


def test_quality_failure_never_enters_review(store):
    run = launch(store)
    lease = store.claim("w")
    payload = compare(store.sources(run["id"]))
    payload["claims"][0]["evidence"][0]["source_id"] = "invented"
    store.checkpoint(lease, payload)
    store.save_blob(lease)
    store.publish(lease)
    snap = store.snapshot("local", run["id"])
    assert snap["run"]["execution"] == "quality_failed"
    assert snap["run"]["review"] == "unavailable"
    with pytest.raises(Conflict):
        store.review(
            "local",
            "local-reviewer",
            run["id"],
            "r1",
            "approve",
            snap["artifact"]["file_sha256"],
            0,
            "checked",
        )


@pytest.mark.parametrize("boundary", ["claim", "checkpoint", "blob", "publish"])
def test_crash_boundaries_recover_without_losing_saved_result(store, boundary):
    run = launch(store)
    old = store.claim("dead", lease_seconds=30)
    payload = compare(store.sources(run["id"]))
    if boundary != "claim":
        store.checkpoint(old, payload)
    if boundary in ("blob", "publish"):
        store.save_blob(old)
    if boundary == "publish":
        store.publish(old)
        assert Store(store.path).claim("replacement") is None
    else:
        with sqlite3.connect(store.path) as db:
            db.execute("UPDATE runs SET lease_until=0")
        replacement = Store(store.path).claim("replacement")
        with pytest.raises(Conflict):
            store.publish(old)
        if boundary == "claim":
            store.checkpoint(replacement, payload)
        store.save_blob(replacement)
        store.publish(replacement)
    snap = Store(store.path).snapshot("local", run["id"])
    assert snap["artifact"]["text"] == payload["text"]
    assert len([e for e in snap["events"] if e["kind"] == "draft_saved"]) == 1
    assert len(snap["attempts"]) == (1 if boundary == "publish" else 2)


def test_missing_blob_is_incomplete_and_cannot_be_approved(store):
    run = launch(store)
    snap = finish(store, run)
    digest = snap["artifact"]["file_sha256"]
    with sqlite3.connect(store.path) as db:
        db.execute("DELETE FROM blobs WHERE digest=?", (digest,))
    snap = Store(store.path).snapshot("local", run["id"])
    assert snap["integrity"] == "incomplete_evidence"
    assert snap["artifact"] is None
    with pytest.raises(Conflict):
        store.review(
            "local", "local-reviewer", run["id"], "r1", "approve", digest, 0, ""
        )


def test_review_exact_version_expiry_conflicts_and_feedback(store):
    run = launch(store)
    snap = finish(store, run)
    digest = snap["artifact"]["file_sha256"]
    with pytest.raises(Conflict):
        store.review(
            "local", "local-reviewer", run["id"], "bad", "approve", "0" * 64, 0, ""
        )
    with pytest.raises(Conflict):
        store.review(
            "local", "local-reviewer", run["id"], "bad", "approve", digest, 1, ""
        )
    r = store.review(
        "local",
        "local-reviewer",
        run["id"],
        "r1",
        "request_changes",
        digest,
        0,
        "Clarify",
    )
    assert r["feedback"] == "Clarify"
    assert (
        store.review(
            "local",
            "local-reviewer",
            run["id"],
            "r1",
            "request_changes",
            digest,
            0,
            "Clarify",
        )
        == r
    )
    with pytest.raises(Conflict):
        store.review(
            "local", "local-reviewer", run["id"], "r1", "approve", digest, 0, ""
        )
    with pytest.raises(Conflict):
        store.review(
            "local", "local-reviewer", run["id"], "r2", "approve", digest, 0, ""
        )
    replacement = launch(store, "launch-2")
    replacement_snap = finish(store, replacement)
    assert replacement_snap["run"]["review"] == "pending"
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE runs SET review_expires=0 WHERE id=?", (replacement["id"],))
    with pytest.raises(Conflict):
        store.review(
            "local", "local-reviewer", replacement["id"], "r3", "approve", digest, 0, ""
        )


@pytest.mark.parametrize("when", ["queued", "claimed", "blob", "ready"])
def test_cancel_race_has_explicit_acknowledgement(store, when):
    run = launch(store)
    lease = None
    if when != "queued":
        lease = store.claim("w")
    if when in ("blob", "ready"):
        store.checkpoint(lease, compare(store.sources(run["id"])))
        store.save_blob(lease)
    if when == "ready":
        store.publish(lease)
        with pytest.raises(Conflict):
            store.cancel("local", "local-reviewer", run["id"], "c1")
        assert store.snapshot("local", run["id"])["run"]["cancellation"] == "rejected"
        return
    store.cancel("local", "local-reviewer", run["id"], "c1")
    assert store.snapshot("local", run["id"])["run"]["cancellation"] == "requested"
    lease = lease or store.claim("w")
    store.ack_cancel(lease)
    snap = store.snapshot("local", run["id"])
    assert snap["run"]["cancellation"] == "acknowledged"
    assert snap["run"]["execution"] == "cancelled"
    assert snap["artifact"] is None
    if when == "blob":
        assert store.reconcile()["orphan_blobs"] == 1


def test_replay_gap_and_cross_scope(store):
    run = launch(store)
    finish(store, run)
    with pytest.raises(KeyError):
        store.snapshot("other", run["id"])
    with pytest.raises(KeyError):
        store.cancel("other", "local-reviewer", run["id"], "c")
    with sqlite3.connect(store.path) as db:
        db.execute("DELETE FROM events WHERE run_id=? AND seq=2", (run["id"],))
    assert store.replay("local", run["id"], 1)["integrity"] == "incomplete_evidence"
    assert store.snapshot("local", run["id"])["integrity"] == "incomplete_evidence"


def test_server_review_rejects_event_gap_even_when_caller_ignores_ui(store):
    run = launch(store)
    snap = finish(store, run)
    with sqlite3.connect(store.path) as db:
        db.execute("DELETE FROM events WHERE run_id=? AND seq=2", (run["id"],))
    with pytest.raises(Conflict):
        store.review(
            "local",
            "local-reviewer",
            run["id"],
            "r1",
            "approve",
            snap["artifact"]["file_sha256"],
            0,
            "",
        )


def test_simultaneous_conflicting_reviews_accept_exactly_one(store):
    import threading

    run = launch(store)
    snap = finish(store, run)
    barrier = threading.Barrier(2)

    def decision(value):
        barrier.wait(timeout=5)
        try:
            return Store(store.path).review(
                "local",
                "local-reviewer",
                run["id"],
                value,
                value,
                snap["artifact"]["file_sha256"],
                0,
                "Concurrent review fixture",
            )
        except Conflict:
            return "conflict"

    with ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(decision, value) for value in ("approve", "reject")]
        results = [future.result(timeout=5) for future in futures]
    assert results.count("conflict") == 1
    accepted = next(r for r in results if isinstance(r, dict))
    final = store.snapshot("local", run["id"])
    assert final["review_record"]["decision"] == accepted["decision"]
    assert final["run"]["review_version"] == 1
    assert sum(e["kind"] == "review_recorded" for e in final["events"]) == 1
