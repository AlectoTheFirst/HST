"""POST /api/cypher runs read-only Cypher for operators."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

import neo4j.exceptions
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from hst.app.auth import require_permission
from hst.app.store import User
from hst.app.tables import (
    MAX_QUERY_BYTES,
    QueryRejected,
    ResultTooLarge,
    audit_outcome,
    result_size,
    run_readonly,
)

router = APIRouter()
log = logging.getLogger(__name__)
require_cypher_run = require_permission("cypher.run")  # B008 forbids this call in an argument default.


class CypherBody(BaseModel):
    query: str
    params: dict = {}


async def record(
    request: Request, user: User, query: str, outcome: str, rows: int = 0, size: int = 0
) -> None:
    """A failed audit write is logged and does not fail the query."""
    try:
        await request.app.state.store.record_cypher_event(
            user_id=user.id,
            query=query,
            outcome=outcome,
            row_count=rows,
            byte_count=size,
            at=datetime.now(UTC),
            origin="rest",
        )
    except Exception:
        log.warning("failed to record cypher event (outcome=%r)", outcome, exc_info=True)


@router.post("/cypher")
async def run_cypher(request: Request, body: CypherBody, user: User = Depends(require_cypher_run)) -> dict:
    if len(body.query.encode()) > MAX_QUERY_BYTES:
        await record(request, user, body.query[:MAX_QUERY_BYTES], "too_large")
        raise HTTPException(413, detail="query too large")
    try:
        table = await asyncio.to_thread(
            run_readonly, request.app.state.settings, body.query, body.params, graph=True
        )
    except (QueryRejected, ResultTooLarge) as exc:
        await record(request, user, body.query, audit_outcome(exc))
        raise HTTPException(400, detail=str(exc)) from exc
    except neo4j.exceptions.ClientError as exc:
        # bad Cypher (syntax and type errors) answers 400 with the reason.
        await record(request, user, body.query, audit_outcome(exc))
        raise HTTPException(400, detail=f"{type(exc).__name__}: {exc}") from exc
    except Exception as exc:
        # An unreachable graph, or any other error that this route does not
        # translate, also writes the audit row.
        await record(request, user, body.query, audit_outcome(exc))
        raise
    rows, size = result_size(table)
    await record(request, user, body.query, "ok", rows, size)
    return table
