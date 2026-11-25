"""The routes of the collection debug capture. They serve the per-source switch,
the captures on disk, a re-parse of a stored payload in isolation, and the
debug bundle.

core/debug_capture.py records the loads. app/debug_reparse.py runs the
re-parse, in this process or, with RUN_EXECUTION=queue, as a `debug.reparse`
job in the process that claims it. A bundle is a zip of the decrypted records,
the stack dumps, the re-parse result and the payload's command outputs. Every
entry is redacted unless the caller asks for the bundle in full. The zip is
streamed as it is built (`debug_capture.iter_bundle`). The routes need
`runs.manage`, as the HTTP traces on the Runs page do.

Each bundle download writes one `evidence_exports` row and one log line with
the account (app/evidence_exports.py). The line is a WARNING for an unredacted
bundle. When the row cannot be written, the server refuses an unredacted bundle
and still sends a redacted one. An unredacted bundle needs `sources.write`.
The admin role holds that permission.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from hst.app import crypto, debug_reparse, evidence_exports, runs_exec
from hst.app.auth import current_user, require_permission
from hst.app.permissions import permissions_for
from hst.app.store import User
from hst.collectors import REGISTRY
from hst.core import debug_capture, rawstore
from hst.core.uid import slug

router = APIRouter(dependencies=[Depends(require_permission("runs.manage"))])

_CAPTURE_LIMIT = 100
RawMode = Literal["redacted", "full", "none"]
# An unredacted bundle holds device credentials. The admin role holds this permission.
FULL_BUNDLE_PERMISSION = "sources.write"


def _raw_path(settings: Any, source: str, host: str, run_id: str) -> Path:
    """The raw file of (source, host, run_id), or 404. The caller gives the
    segments. The path must resolve inside the raw store."""
    if not rawstore._RUN_ID.match(run_id):
        raise HTTPException(404, detail="no such payload")
    raw_dir = settings.raw_dir.resolve()
    path = rawstore.raw_path_of(settings.raw_dir, source, host, run_id).resolve()
    if not path.is_relative_to(raw_dir) or not path.is_file():
        raise HTTPException(404, detail="no such payload")
    return path


def _capture_rows(settings: Any, names: dict[str, str]) -> list[dict[str, Any]]:
    key = crypto.dek(settings)
    rows = []
    for f in debug_capture.capture_files(settings.raw_dir):
        reader = debug_capture.RecordReader(f.path, key)
        loads = debug_capture.summarize(reader)
        last = loads[-1] if loads else {}
        rows.append(
            {
                "id": debug_capture.capture_id(f.source, f.host, f.run_id),
                "source": f.source,
                "source_name": names.get(f.source, f.source),
                "host": f.host,
                "run_id": f.run_id,
                "loads": len(loads),
                "begin_ms": last.get("begin_ms"),
                "last_ms": last.get("last_ms"),
                "finished": last.get("finished", False),
                "status": last.get("status"),
                "error": last.get("error"),
                "open_steps": [
                    {"step": s.get("step"), "command": s.get("command"), "started_ms": s.get("ts_ms")}
                    for s in last.get("open_steps") or []
                ],
                "peak_rss_kb": last.get("peak_rss_kb"),
                "has_stack": f.has_stack,
                "unreadable_lines": reader.unreadable,
                "size": f.size,
            }
        )
    rows.sort(key=lambda r: r["begin_ms"] or 0, reverse=True)
    return rows[:_CAPTURE_LIMIT]


@router.get("/debug-capture")
async def overview(request: Request) -> dict:
    """Every source with its switch, and the captures on disk, newest first."""
    settings = request.app.state.settings
    rows = await request.app.state.store.list_sources()
    names = {slug(r.name): r.name for r in rows}
    on = debug_capture.switches(settings)
    captures = await asyncio.to_thread(_capture_rows, settings, names)
    return {
        "sources": [
            {
                "name": r.name,
                "type": r.type,
                "until_ms": (on.get(r.name) or {}).get("until_ms"),
                "by": (on.get(r.name) or {}).get("by"),
            }
            for r in sorted(rows, key=lambda r: r.name)
        ],
        "captures": captures,
        "limits": {
            "capture_hours": settings.hst_debug_capture_hours,
            "stack_after_s": settings.hst_debug_stack_after_s,
            "reparse_memory_mb": settings.hst_debug_reparse_memory_mb,
            "reparse_timeout_s": settings.hst_debug_reparse_timeout_s,
        },
    }


class SwitchBody(BaseModel):
    enabled: bool


@router.put("/debug-capture/sources/{name}")
async def switch(request: Request, name: str, body: SwitchBody, user: User = Depends(current_user)) -> dict:
    """Turn capture on for `hst_debug_capture_hours`, or off."""
    settings = request.app.state.settings
    if await request.app.state.store.get_source(name) is None:
        raise HTTPException(404, detail=f"unknown source {name!r}")
    until = int(time.time() * 1000) + settings.hst_debug_capture_hours * 3_600_000 if body.enabled else None
    await asyncio.to_thread(debug_capture.set_switch, settings, name, until_ms=until, by=user.username)
    return {"name": name, "until_ms": until, "by": user.username if until else None}


@router.get("/debug-capture/payloads")
async def payloads(request: Request, source: str, limit: int = Query(10, ge=1, le=50)) -> dict:
    """The newest stored payloads of one source, with their re-parse state."""
    settings = request.app.state.settings
    store = request.app.state.store
    if await store.get_source(source) is None:
        raise HTTPException(404, detail=f"unknown source {source!r}")

    def listing() -> list[dict[str, Any]]:
        out = []
        for f in rawstore.raw_files(settings.raw_dir, source, limit):
            out.append(
                {
                    "id": debug_capture.capture_id(f.source, f.host, f.run_id),
                    "source": f.source,
                    "host": f.host,
                    "run_id": f.run_id,
                    "fetch_ts_ms": f.fetch_ts_ms,
                    "size": f.size,
                    "has_capture": rawstore.sibling(f.path, rawstore.DEBUG_SUFFIX).is_file(),
                    "reparse": debug_reparse.state(settings, f.source, f.host, f.run_id),
                }
            )
        return out

    rows = await asyncio.to_thread(listing)
    for row in rows:
        row["reparse"] = await debug_reparse.resolve(store, row["reparse"])
    return {"source": source, "payloads": rows}


class ReparseBody(BaseModel):
    source: str
    host: str = ""
    run_id: str


@router.post("/debug-capture/reparse", status_code=202)
async def reparse(request: Request, body: ReparseBody, user: User = Depends(current_user)) -> dict:
    """Parse one stored payload again in a child process. With
    RUN_EXECUTION=inline the child belongs to this process. With
    RUN_EXECUTION=queue it belongs to the process whose executor claims the
    queued `debug.reparse` job (`job_id`)."""
    settings = request.app.state.settings
    store = request.app.state.store
    row = await store.get_source(body.source)
    if row is None:
        raise HTTPException(404, detail=f"unknown source {body.source!r}")
    if row.type not in REGISTRY:
        raise HTTPException(400, detail=f"{body.source} has no collector type {row.type!r}")
    _raw_path(settings, body.source, body.host, body.run_id)
    # The host as the directory segment of the raw store. The payload listing uses the same segment.
    host = slug(body.host)
    if settings.run_execution == "queue":
        job = await debug_reparse.enqueue(store, settings, row.name, host, body.run_id, user.id)
        if job is None:
            raise HTTPException(409, detail="a re-parse of this payload is already running")
        return {"state": debug_reparse.RUNNING, "job_id": job.id}
    if not debug_reparse.start(settings, row.type, slug(body.source), host, body.run_id):
        raise HTTPException(409, detail="a re-parse of this payload is already running")
    return {"state": debug_reparse.RUNNING}


def _download(chunks: Iterator[bytes], name: str) -> StreamingResponse:
    """A bundle, sent as it is built. The status and the headers go before the
    first byte of the zip. The checks that can refuse a bundle run before
    `_download`."""
    return StreamingResponse(
        chunks,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


async def _known(request: Request, raw: RawMode) -> list[str]:
    """The credential values that the sources are configured with. They are
    removed from every entry of a bundle that is not full. A bundle is not built
    when the credentials of the sources cannot be read."""
    if raw == "full":
        return []
    try:
        return await runs_exec.configured_secrets(request.app.state.store, request.app.state.settings)
    except Exception:
        raise HTTPException(
            503, detail="the sources' credentials could not be read, so the redacted bundle was not built"
        ) from None


def _check_full(user: User, raw: RawMode) -> None:
    if raw == "full" and FULL_BUNDLE_PERMISSION not in permissions_for(user.role):
        raise HTTPException(403, detail=f"requires permission: {FULL_BUNDLE_PERMISSION}")


async def _record(
    request: Request,
    user: User,
    *,
    kind: str,
    raw: RawMode,
    source: str,
    host: str,
    run_id: str,
    payloads: int,
) -> None:
    """Write the export record. An unredacted bundle needs FULL_BUNDLE_PERMISSION
    and is not sent without its record."""
    _check_full(user, raw)
    written = await evidence_exports.record(
        request, user, kind=kind, raw_mode=raw, source=source, host=host, run_id=run_id, payloads=payloads
    )
    if not written and raw == "full":
        raise HTTPException(
            503, detail="the export record could not be written, so the unredacted bundle was not sent"
        )


@router.get("/debug-capture/bundle")
async def payload_bundle(
    request: Request,
    source: str,
    run_id: str,
    host: str = "",
    raw: RawMode = "redacted",
    user: User = Depends(current_user),
) -> StreamingResponse:
    """The bundle of one stored payload, with its captures, re-parse and outputs."""
    settings = request.app.state.settings
    path = _raw_path(settings, source, host, run_id)
    known = await _known(request, raw)
    await _record(
        request, user, kind="payload_bundle", raw=raw, source=source, host=host, run_id=run_id, payloads=1
    )
    chunks = debug_capture.iter_bundle(
        settings.raw_dir, crypto.dek(settings), [path], raw_mode=raw, known=known
    )
    return _download(chunks, f"hst-debug-{slug(source)}-{run_id}.zip")


@router.get("/runs/{run_id}/debug-bundle")
async def run_bundle(
    request: Request, run_id: int, raw: RawMode = "redacted", user: User = Depends(current_user)
) -> StreamingResponse:
    """The bundle of every capture that a run made. A capture belongs to the
    run when its load began between the start and the finish of the run, and
    its source is the source of the run or, for a cycle, any source. 404 when
    the run made no capture."""
    settings = request.app.state.settings
    run = await request.app.state.store.get_run(run_id)
    if run is None:
        raise HTTPException(404, detail=f"no run {run_id}")
    started = int(run.started_at.timestamp() * 1000)
    finished = int((run.finished_at or datetime.now(UTC)).timestamp() * 1000)
    rows = await request.app.state.store.list_sources()
    single = slug(run.source) if any(r.name == run.source for r in rows) else None

    def matching() -> list[Path]:
        key = crypto.dek(settings)
        out = []
        for f in debug_capture.capture_files(settings.raw_dir):
            if single is not None and f.source != single:
                continue
            records = debug_capture.RecordReader(f.path, key)
            if any(
                r.get("event") == "begin" and started <= int(r.get("ts_ms") or 0) <= finished for r in records
            ):
                out.append(f.raw_path)
        return out

    paths = await asyncio.to_thread(matching)
    if not paths:
        raise HTTPException(404, detail=f"run {run_id} made no debug capture")
    known = await _known(request, raw)
    await _record(
        request,
        user,
        kind="run_bundle",
        raw=raw,
        source=run.source,
        host="",
        run_id=str(run.id),
        payloads=len(paths),
    )
    extra = {
        "run.json": {
            "id": run.id,
            "source": run.source,
            "status": run.status,
            "started_at": run.started_at.isoformat(),
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            "detail": run.detail,
        }
    }
    chunks = debug_capture.iter_bundle(
        settings.raw_dir, crypto.dek(settings), paths, raw_mode=raw, extra=extra, known=known
    )
    return _download(chunks, f"hst-debug-run-{run_id}.zip")
