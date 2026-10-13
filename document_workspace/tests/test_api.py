import pytest
from fastapi.testclient import TestClient

from document_workspace.server import create_app
from document_workspace.store import Store
from document_workspace.tests.test_workspace import body


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "w.db", "test-bootstrap-token", 8765)
    with TestClient(app, base_url="http://127.0.0.1:8765") as c:
        yield c, app.state.store


def login(c):
    r = c.post(
        "/api/session",
        headers={
            "Authorization": "Bearer test-bootstrap-token",
            "Origin": "http://127.0.0.1:8765",
        },
    )
    assert r.status_code == 200
    return {"X-CSRF-Token": r.json()["csrf"], "Origin": "http://127.0.0.1:8765"}


def test_session_host_origin_and_scope(client):
    c, _ = client
    route = "/api/workspaces/local/runs"
    assert c.post(route, json={}).status_code == 401
    assert (
        c.post("/api/session", headers={"Authorization": "Bearer wrong"}).status_code
        == 401
    )
    headers = login(c)
    assert c.post(route, json={"key": "k", "sources": body()}).status_code == 403
    assert (
        c.post(
            route, headers={**headers, "Origin": "https://evil.example"}, json={}
        ).status_code
        == 403
    )
    assert c.get("/", headers={"Host": "evil.example"}).status_code == 400
    assert c.get("/api/workspaces/other/runs/guess").status_code == 404
    assert (
        c.get("/api/workspaces/local/runs/guess").headers["cache-control"] == "no-store"
    )


def test_browser_disconnect_and_api_restart_do_not_own_execution(client):
    c, store = client
    h = login(c)
    route = "/api/workspaces/local/runs"
    admitted = c.post(route, headers=h, json={"key": "same", "sources": body()})
    assert admitted.status_code == 200
    run_id = admitted.json()["id"]
    assert (
        c.post(route, headers=h, json={"key": "same", "sources": body()}).json()["id"]
        == run_id
    )
    assert (
        c.post(
            route, headers=h, json={"key": "same", "sources": body(current="Other")}
        ).status_code
        == 409
    )
    # No active browser subscription or API process is required by the worker.
    from document_workspace.worker import execute

    execute(Store(store.path), Store(store.path).claim("separate-worker"))
    second = TestClient(
        create_app(store.path, "test-bootstrap-token", 8765),
        base_url="http://127.0.0.1:8765",
    )
    h2 = login(second)
    snap = second.get(f"{route}/{run_id}").json()
    assert snap["run"]["execution"] == "draft_ready"
    assert "lease_token" not in snap["run"]
    r = second.post(
        f"{route}/{run_id}/review",
        headers=h2,
        json={
            "key": "review1",
            "decision": "approve",
            "file_sha256": snap["artifact"]["file_sha256"],
            "review_version": 0,
            "feedback": "Reviewed exact source pairs",
        },
    )
    assert r.status_code == 200
    assert second.get(f"{route}/{run_id}").json()["run"]["review"] == "approve"
    assert (
        second.get(f"{route}/{run_id}/draft").content.decode()
        == snap["artifact"]["text"]
    )
    second.close()


def test_durable_worker_is_a_separate_process(client):
    _, store = client
    run = store.launch("local", "local-reviewer", "process", body())
    # Spawn an ordinary finite local worker invocation with the real CLI.
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "document_workspace.worker",
            "--db",
            str(store.path),
            "--once",
        ],
        check=True,
        capture_output=True,
    )
    assert b"SYNTHETIC" in result.stdout
    assert store.snapshot("local", run["id"])["run"]["execution"] == "draft_ready"


def test_malformed_command_never_mutates_state(client):
    c, store = client
    h = login(c)
    assert (
        c.post(
            "/api/workspaces/local/runs",
            headers=h,
            json={"key": "x", "sources": body(), "workspace": "other"},
        ).status_code
        == 422
    )
    assert (
        c.post(
            "/api/workspaces/local/runs",
            headers=h,
            json={"key": "x", "sources": {"prior": 1, "current": 2}},
        ).status_code
        == 422
    )
    assert (
        c.post("/api/workspaces/local/runs", headers=h, content=b"{").status_code == 422
    )
    assert (
        c.post(
            "/api/workspaces/local/runs", headers=h, content=b"x" * 650001
        ).status_code
        == 413
    )
    assert store.claim("w") is None


def test_review_and_download_fail_closed_on_corrupt_projection(client):
    import json
    import sqlite3

    from document_workspace.tests.test_workspace import finish

    c, store = client
    headers = login(c)
    run = store.launch("local", "local-reviewer", "corrupt-api", body())
    snap = finish(store, run)
    route = "/api/workspaces/local/runs/" + run["id"]
    with sqlite3.connect(store.path) as db:
        payload = json.loads(db.execute("SELECT payload FROM manifests").fetchone()[0])
        payload["text"] = "Changed display"
        db.execute("UPDATE manifests SET payload=?", (json.dumps(payload),))
    assert c.get(route).json()["integrity"] == "incomplete_evidence"
    assert c.get(route + "/draft").status_code == 409
    assert (
        c.post(
            route + "/review",
            headers=headers,
            json={
                "key": "r1",
                "decision": "approve",
                "file_sha256": snap["artifact"]["file_sha256"],
                "review_version": 0,
                "feedback": "",
            },
        ).status_code
        == 409
    )
    assert store.snapshot("local", run["id"])["review_record"] is None


def test_review_api_rejects_gap(client):
    import sqlite3

    from document_workspace.tests.test_workspace import finish

    c, store = client
    headers = login(c)
    run = store.launch("local", "local-reviewer", "gap-api", body())
    snap = finish(store, run)
    with sqlite3.connect(store.path) as db:
        db.execute("DELETE FROM events WHERE run_id=? AND seq=2", (run["id"],))
    response = c.post(
        "/api/workspaces/local/runs/" + run["id"] + "/review",
        headers=headers,
        json={
            "key": "r1",
            "decision": "approve",
            "file_sha256": snap["artifact"]["file_sha256"],
            "review_version": 0,
            "feedback": "",
        },
    )
    assert response.status_code == 409
    assert store.snapshot("local", run["id"])["review_record"] is None


def test_source_locator_utf8_boundary_and_run_scope(client):
    from document_workspace.tests.test_workspace import finish

    c, store = client
    login(c)
    run = store.launch("local", "local-reviewer", "spans", body("Café\n", "Café ☕\n"))
    snap = finish(store, run)
    ref = snap["artifact"]["claims"][0]["evidence"][1]
    response = c.get(ref["locator"])
    assert response.content.decode() == ref["quote"]
    assert response.headers["X-Source-SHA256"] == ref["source_sha256"]
    assert c.get(ref["locator"].split("?")[0] + "?start=4&end=5").status_code == 422
    assert c.get(ref["locator"].replace("/local/", "/other/")).status_code == 404
    another = store.launch("local", "local-reviewer", "another", body())
    assert c.get(ref["locator"].replace(run["id"], another["id"])).status_code == 404


def test_scoped_launch_key_resolution_recovers_admitted_run_without_execution(client):
    c, store = client
    route = "/api/workspaces/local/launches/lost-ack"
    assert c.get(route).status_code == 401
    login(c)
    assert c.get(route).status_code == 404
    original = body("Café ☕ — ancien.\r\n", "Café ☕ — actuel.\r\n")
    run = store.launch("local", "local-reviewer", "lost-ack", original)
    resolved = c.get(route)
    assert resolved.status_code == 200
    assert resolved.json() == {"id": run["id"], "execution": "queued"}
    snap = c.get("/api/workspaces/local/runs/" + resolved.json()["id"]).json()
    assert snap["sources"][0]["text"] == original["prior"]["text"]
    assert snap["sources"][1]["text"] == original["current"]["text"]
    assert snap["attempts"] == []
    assert c.get("/api/workspaces/other/launches/lost-ack").status_code == 404
    store.launch("local", "another-reviewer", "private-key", original)
    assert c.get("/api/workspaces/local/launches/private-key").status_code == 404
    assert c.get(route).headers["cache-control"] == "no-store"
