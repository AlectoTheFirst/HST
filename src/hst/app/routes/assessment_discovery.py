"""GET /api/assessment-options returns the named object choices of the guided assessment workflow."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from hst.app.auth import require_permission
from hst.assessment.discovery import search_options

router = APIRouter()


@router.get("/assessment-options", dependencies=[Depends(require_permission("graph.read"))])
async def assessment_options(
    request: Request,
    snapshot: str = Query(min_length=1, max_length=32),
    kind: str = Query(default="all", max_length=100),
    q: str = Query(default="", max_length=200),
    uid: str | None = Query(default=None, min_length=1, max_length=500),
    assessment_id: str | None = Query(default=None, min_length=1, max_length=200),
    limit: int = Query(default=50, ge=1, le=100),
    destination: str = Query(default="", max_length=500),
    client: str = Query(default="", max_length=500),
    location: str = Query(default="", max_length=500),
    application: str = Query(default="", max_length=500),
) -> dict[str, Any]:
    dependencies = []
    if assessment_id:
        store = request.app.state.store
        if not hasattr(store, "get_assessment"):
            raise HTTPException(503, "Assessment storage is unavailable.")
        if await store.get_assessment(assessment_id) is None:
            raise HTTPException(404, "Assessment not found.")
        runs = await store.list_analysis_runs(assessment_id, limit=100)
        run = next(
            (
                r
                for r in runs
                if r.state == "completed"
                and r.result
                and any(str(ref.get("snapshot")) == snapshot for ref in r.snapshot_refs)
            ),
            None,
        )
        if run:
            dependencies = run.result.get("dependencies", [])
    clues: dict[str, Any] = {
        key: value
        for key, value in {
            "destination": destination,
            "client": client,
            "location": location,
            "application": application,
        }.items()
        if value
    }
    if kind == "service" and hasattr(request.app.state.store, "list_requirements"):
        saved = await request.app.state.store.list_requirements(limit=1000)
        if saved:
            clues["saved_requirements"] = [item.as_dict() for item in saved]
    try:
        result = await asyncio.to_thread(
            search_options,
            request.app.state.settings,
            snapshot,
            kind,
            q,
            uid,
            dependencies=dependencies,
            limit=limit,
            **clues,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if assessment_id:
        result["suggestion_scope"] = "latest matching completed analysis of the 100 most recent runs"
    return result
