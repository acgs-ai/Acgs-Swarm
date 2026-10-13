"""Loopback-only application commands and projections, separate from workers."""

import argparse
import hmac
import secrets
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from .store import Conflict, Store

WORKSPACE = "local"
ACTOR = "local-reviewer"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Source(StrictModel):
    name: StrictStr = Field(min_length=1, max_length=120)
    text: StrictStr


class Sources(StrictModel):
    prior: Source
    current: Source


class Launch(StrictModel):
    key: StrictStr = Field(min_length=1, max_length=128)
    sources: Sources


class Command(StrictModel):
    key: StrictStr = Field(min_length=1, max_length=128)


class Review(Command):
    decision: StrictStr
    file_sha256: StrictStr = Field(pattern="^[0-9a-f]{64}$")
    review_version: StrictInt = Field(ge=0)
    feedback: StrictStr = Field(max_length=4000)


def create_app(db_path, bootstrap_token, port=8765):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    store = Store(db_path)
    app.state.store = store
    session_id, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    @app.middleware("http")
    async def boundaries(request, call_next):
        if request.headers.get("host") not in hosts:
            return JSONResponse({"detail": "Loopback host required"}, status_code=400)
        origin = request.headers.get("origin")
        if origin and origin not in origins:
            return JSONResponse(
                {"detail": "Origin is outside this local workspace"}, status_code=403
            )
        if request.method == "POST":
            # Bound the actual stream too, including requests without Content-Length.
            size, chunks = 0, []
            async for chunk in request.stream():
                size += len(chunk)
                if size > 650000:
                    return JSONResponse(
                        {"detail": "Request exceeds local transport limit"},
                        status_code=413,
                    )
                chunks.append(chunk)
            request._body = b"".join(chunks)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self'; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        return response

    @app.exception_handler(Conflict)
    async def conflict_handler(_, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(ValueError)
    async def invalid_handler(_, exc):
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @app.exception_handler(KeyError)
    async def missing_handler(_, __):
        return JSONResponse(
            {"detail": "Resource unavailable in this workspace"}, status_code=404
        )

    def authenticated(request: Request):
        if not hmac.compare_digest(
            request.cookies.get("acgs_local_session", ""), session_id
        ):
            raise HTTPException(401, "Open a local session first")
        if request.method == "POST" and (
            request.headers.get("origin") not in origins
            or not hmac.compare_digest(request.headers.get("x-csrf-token", ""), csrf)
        ):
            raise HTTPException(403, "Local session command token required")

    def scoped(workspace: str, _: None = Depends(authenticated)):
        if workspace != WORKSPACE:
            raise HTTPException(404, "Workspace unavailable")

    @app.post("/api/session")
    def session(request: Request):
        supplied = request.headers.get("authorization", "")
        if not hmac.compare_digest(supplied, "Bearer " + bootstrap_token):
            raise HTTPException(401, "Local session token is invalid")
        response = JSONResponse(
            {"csrf": csrf, "workspace": WORKSPACE, "reviewer": ACTOR}
        )
        response.set_cookie(
            "acgs_local_session", session_id, httponly=True, samesite="strict", path="/"
        )
        return response

    @app.get("/api/session", dependencies=[Depends(authenticated)])
    def session_state():
        return {"csrf": csrf, "workspace": WORKSPACE, "reviewer": ACTOR}

    prefix = "/api/workspaces/{workspace}/runs"

    @app.post(prefix, dependencies=[Depends(scoped)])
    def launch(workspace: str, command: Launch):
        run = store.launch(workspace, ACTOR, command.key, command.sources.model_dump())
        # Admission acknowledgement is sent only after the SQLite transaction.
        return {"id": run["id"], "execution": run["execution"]}

    @app.get(
        "/api/workspaces/{workspace}/launches/{launch_key}",
        dependencies=[Depends(scoped)],
    )
    def resolve_launch(workspace: str, launch_key: str):
        return store.resolve_launch(workspace, ACTOR, launch_key)

    @app.get(prefix + "/{run_id}", dependencies=[Depends(scoped)])
    def snapshot(workspace: str, run_id: str):
        return store.snapshot(workspace, run_id)

    @app.get(prefix + "/{run_id}/events", dependencies=[Depends(scoped)])
    def replay(workspace: str, run_id: str, after: int = 0):
        return store.replay(workspace, run_id, after)

    @app.post(prefix + "/{run_id}/review", dependencies=[Depends(scoped)])
    def review(workspace: str, run_id: str, command: Review):
        return store.review(
            workspace,
            ACTOR,
            run_id,
            command.key,
            command.decision,
            command.file_sha256,
            command.review_version,
            command.feedback,
        )

    @app.post(prefix + "/{run_id}/cancel", dependencies=[Depends(scoped)])
    def cancel(workspace: str, run_id: str, command: Command):
        return store.cancel(workspace, ACTOR, run_id, command.key)

    @app.get(prefix + "/{run_id}/draft", dependencies=[Depends(scoped)])
    def draft(workspace: str, run_id: str):
        snap = store.snapshot(workspace, run_id)
        if not snap["artifact"] or snap["integrity"] != "complete":
            raise Conflict("Saved draft evidence is incomplete")
        return Response(
            snap["artifact"]["text"].encode("utf-8"),
            media_type="text/markdown",
            headers={
                "Content-Disposition": 'attachment; filename="procedure-change-brief.md"'
            },
        )

    @app.get(prefix + "/{run_id}/sources/{source_id}", dependencies=[Depends(scoped)])
    def source_span(
        workspace: str,
        run_id: str,
        source_id: str,
        start: int = 0,
        end: int | None = None,
    ):
        snap = store.snapshot(workspace, run_id)
        source = next((s for s in snap["sources"] if s["id"] == source_id), None)
        if source is None:
            raise HTTPException(404, "Source unavailable in this workspace/run")
        raw = source["text"].encode("utf-8")
        end = len(raw) if end is None else end
        if not 0 <= start <= end <= len(raw):
            raise HTTPException(422, "Invalid UTF-8 source span")
        try:
            quote = raw[start:end].decode("utf-8")
            raw[:start].decode("utf-8")
        except UnicodeError as exc:
            raise HTTPException(
                422, "Source span must respect UTF-8 boundaries"
            ) from exc
        return Response(
            quote.encode("utf-8"),
            media_type="text/plain",
            headers={"X-Source-SHA256": source["file_sha256"]},
        )

    dist = Path(__file__).parent / "ui" / "dist"
    if dist.exists():
        app.mount("/", StaticFiles(directory=dist, html=True))
    else:

        @app.get("/")
        def missing_ui():
            return JSONResponse(
                {"detail": "Build document_workspace/ui before opening the UI"},
                status_code=503,
            )

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="document_workspace/data/workspace.db")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    token = secrets.token_urlsafe(32)
    print(f"Local workspace: http://127.0.0.1:{args.port}", flush=True)
    print("Ephemeral session token (paste in local UI): " + token, flush=True)
    uvicorn.run(
        create_app(args.db, token, args.port),
        host="127.0.0.1",
        port=args.port,
        access_log=False,
    )


if __name__ == "__main__":
    main()
