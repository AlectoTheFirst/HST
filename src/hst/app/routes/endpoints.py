"""GET /api/endpoints returns the endpoints of one run, filtered and paged by cursor.

The filter grammar is core/filters.py's, given as query parameters:

- `ip`, `subnet`, `range_start` with `range_end`: address filters.
- `q` with optional repeated `q_field` (name, hostname, mac, vendor, port):
  case-insensitive substring.
- `regex` with optional repeated `regex_field` (name, hostname): a guarded
  whole-value pattern.
- `site`, `vrf`, `routing_domain`, `segment`, `device`, `port`, each
  repeatable: scopes.
- `last_seen_after`, `last_seen_before`: ISO 8601, or epoch seconds or
  milliseconds.

`snapshot` names the run. Without it the current run is read, or the run of
`cursor` when one is given. `limit` is the page size. The answer has the
run, the page's items, `next_cursor` (null on the last page) and the number
of matching endpoints, exact up to `filters.COUNT_CAP` (`total_capped`, with
`total_exact` false past it).

A filter, regex or cursor that cannot be used is a 400 naming the problem.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from hst.app.auth import require_permission
from hst.app.routes.run_lease import reading
from hst.core import db as dbmod
from hst.core import entity_read
from hst.core import filters as filtermod
from hst.core import snapshot as snapshotmod

router = APIRouter()
_session = dbmod.session  # Tests replace this name.

ENDPOINT_PAGE = 100
ENDPOINT_PAGE_MAX = 500

Repeated = Annotated[list[str] | None, Query()]


def filter_from(values: dict[str, Any]) -> filtermod.EntityFilter:
    try:
        return filtermod.parse_filter(values)
    except filtermod.FilterError as exc:
        raise HTTPException(400, detail=str(exc)) from exc


def endpoint_filter_values(
    ip: str | None = None,
    subnet: str | None = None,
    range_start: str | None = None,
    range_end: str | None = None,
    q: str | None = None,
    q_field: Annotated[list[filtermod.TextField] | None, Query()] = None,
    regex: str | None = None,
    regex_field: Annotated[list[filtermod.RegexField] | None, Query()] = None,
    vrf: Repeated = None,
    routing_domain: Repeated = None,
    device: Repeated = None,
    port: Repeated = None,
    last_seen_after: str | None = None,
    last_seen_before: str | None = None,
) -> dict[str, Any]:
    """The filter parameters every endpoint list takes, before the scopes a
    list may take itself (`site`, `segment`)."""
    return {
        "ip": ip,
        "subnet": subnet,
        "range_start": range_start,
        "range_end": range_end,
        "text": q,
        "text_fields": q_field,
        "regex": regex,
        "regex_fields": regex_field,
        "vrf": vrf,
        "routing_domain": routing_domain,
        "device": device,
        "port": port,
        "last_seen_after": last_seen_after,
        "last_seen_before": last_seen_before,
    }


def endpoint_filter(
    values: Annotated[dict[str, Any], Depends(endpoint_filter_values)],
    site: Repeated = None,
    segment: Repeated = None,
) -> filtermod.EntityFilter:
    return filter_from({**values, "site": site, "segment": segment})


def cursor_of(text: str | None, kind: str, f: filtermod.EntityFilter) -> filtermod.Cursor | None:
    if not text:
        return None
    try:
        return filtermod.decode_cursor(text, kind=kind, filter_print=f.fingerprint())
    except filtermod.FilterError as exc:
        raise HTTPException(400, detail=str(exc)) from exc


def pinned_run(s: Any, named: str | None, cursor: filtermod.Cursor | None) -> int | None:
    """The run that a paged read answers from. It is the run of `snapshot`, or
    else the run of the cursor, or else None for the current run. A cursor of
    another run than the named run is a 400. A run whose graph is gone is a 404."""
    try:
        cts = snapshotmod.parse_snapshot_id(named)
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    if cursor is not None and cursor.run is not None:
        if cts is not None and cts != cursor.run:
            raise HTTPException(400, detail="the cursor belongs to another run than snapshot")
        cts = cursor.run
    if cts is not None:
        try:
            snapshotmod.require_retained(s, cts)
        except ValueError as exc:
            raise HTTPException(404, detail=f"unknown run: {cts}") from exc
    return cts


@router.get("/endpoints", dependencies=[Depends(require_permission("graph.read"))])
def list_endpoints(
    request: Request,
    f: Annotated[filtermod.EntityFilter, Depends(endpoint_filter)],
    cursor: str | None = None,
    snapshot: str | None = None,
    limit: Annotated[int, Query(ge=1, le=ENDPOINT_PAGE_MAX)] = ENDPOINT_PAGE,
) -> dict[str, Any]:
    """One page of the endpoints of a run that match the filter, ordered by
    name then uid."""
    after = cursor_of(cursor, "endpoint", f)
    settings = request.app.state.settings
    with _session(settings) as s:
        resolved = snapshotmod.resolve(s, settings, pinned_run(s, snapshot, after))
        snap = snapshotmod.snap_param(resolved.cts)
        with reading(request, s, resolved):
            try:
                page = entity_read.read_page(
                    s, "endpoint", f, snap=snap, run=resolved.cts, cursor=after, limit=limit
                )
            except filtermod.FilterError as exc:
                raise HTTPException(400, detail=str(exc)) from exc
            items = entity_read.read_endpoints(s, page.uids, snap=snap)
    return {
        "snapshot": resolved.cts,
        "items": items,
        "next_cursor": page.next_cursor,
        "total_capped": page.total_capped,
        "total_exact": page.total_exact,
        "limit": limit,
    }
