"""HST map API routes.

The routes read the side store and the marker files. A handler that also reads
the graph imports `hst.map.tier3` in its body. `/device` reads the graph on a
warm run only.
"""

from __future__ import annotations

import asyncio
import gzip
import json
from collections.abc import AsyncIterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import pyarrow as pa
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.sse import EventSourceResponse, ServerSentEvent

from hst.app.auth import require_permission
from hst.app.routes.run_lease import leased
from hst.map import events, layout_read, markers, port_groups, timeline
from hst.map.tiers import read
from hst.map.tiers.schemas import DELTA_OF, KEYS, SCHEMA_VERSIONS, SCHEMAS, TILED

router = APIRouter(prefix="/hst")
READ = [Depends(require_permission("graph.read"))]
INTERFACES = [Depends(require_permission("interfaces.read"))]
TIERS = tuple(KEYS)


def _dirs(request: Request) -> tuple[Path, Path]:
    settings = request.app.state.settings
    return settings.manifests_dir, settings.sidestore_dir


def _run(request: Request, snapshot: str | None) -> dict[str, Any]:
    """The marker of the run that `snapshot` names, or of the newest run when `snapshot` is absent."""
    markers_dir, _ = _dirs(request)
    if snapshot is None:
        chain = timeline.chain(markers_dir)
        if not chain:
            raise HTTPException(404, detail="no run published")
        key = chain[-1]
    elif snapshot.startswith("sim:"):
        raise HTTPException(404, detail=f"unknown run {snapshot}")
    else:
        try:
            key = int(snapshot)
        except ValueError:
            raise HTTPException(404, detail=f"unknown run {snapshot}") from None
    marker = markers.read(markers_dir, key)
    if marker is None:
        raise HTTPException(404, detail=f"unknown run {key}")
    return marker


def _ready(marker: Mapping[str, Any]) -> int:
    if not marker.get("tiers_ready"):
        raise HTTPException(409, detail=f"run {marker['key']}: tiers not ready")
    return int(marker["key"])


def _json(request: Request, body: Any) -> Response:
    data = json.dumps(body, separators=(",", ":"), default=str).encode()
    if "gzip" in request.headers.get("accept-encoding", ""):
        return Response(
            gzip.compress(data), media_type="application/json", headers={"Content-Encoding": "gzip"}
        )
    return Response(data, media_type="application/json")


def _columnar(rows: Sequence[Mapping[str, Any]] | pa.Table, columns: Sequence[str]) -> dict[str, Any]:
    if isinstance(rows, pa.Table):
        data = rows.to_pydict()
        return {
            "columns": list(columns),
            "rows": [list(r) for r in zip(*(data[c] for c in columns), strict=True)],
        }
    return {"columns": list(columns), "rows": [[r.get(c) for c in columns] for r in rows]}


def _tile(sidestore_dir: Path, key: int, chain: list[int], tile: str | None) -> None:
    blocks = read.tier_at(sidestore_dir, "render_t0", key, chain)
    if tile not in set(blocks.column("uid").to_pylist()):
        raise HTTPException(404, detail=f"unknown tile {tile}")


def _device(sidestore_dir: Path, key: int, chain: list[int], uid: str) -> None:
    devices = read.tier_at(sidestore_dir, "render_t1", key, chain)
    if uid not in set(devices.column("uid").to_pylist()):
        raise HTTPException(404, detail=f"unknown device {uid}")


@router.get("/timeline", dependencies=READ)
def get_timeline(request: Request) -> dict[str, Any]:
    markers_dir, _ = _dirs(request)
    return timeline.timeline(markers_dir)


@router.get("/tier", dependencies=READ)
def get_tier(
    request: Request,
    name: str = Query(...),
    snapshot: str | None = None,
    tile: str | None = None,
    device: str | None = None,
) -> Response:
    """A tier table at the run. `render_t2_port_groups` is derived from the ports and cables of the tile."""
    derived = name == port_groups.NAME
    if name not in TIERS and not derived:
        raise HTTPException(404, detail=f"unknown tier {name}")
    tiled = derived or name in TILED
    if tiled and tile is None:
        raise HTTPException(400, detail=f"{name} is tiled: tile is required")
    if device is not None and name not in read.DEVICE_FILTERED:
        raise HTTPException(400, detail=f"{name} has no device filter")
    markers_dir, sidestore = _dirs(request)
    key = _ready(_run(request, snapshot))
    with leased(request, [key]):
        chain = timeline.chain(markers_dir)
        try:
            if tiled:
                _tile(sidestore, key, chain, tile)
            if derived:
                version = port_groups.SCHEMA_VERSION
                answer = _columnar(read.port_groups_at(sidestore, key, chain, tile), port_groups.COLUMNS)
            else:
                version = SCHEMA_VERSIONS[name]
                table = read.tier_at(sidestore, name, key, chain, tile if tiled else None)
                if device is not None:
                    _device(sidestore, key, chain, device)
                    table = read.device_filter(table, name, device)
                answer = _columnar(table, SCHEMAS[name].names)
        except read.NotFound as exc:
            raise HTTPException(404, detail=str(exc)) from None
        body = {
            "name": name,
            "snapshot": key,
            "tile": tile if tiled else None,
            **({"device": device} if device is not None else {}),
            "schema_version": version,
            **answer,
        }
        return _json(request, body)


@router.get("/delta", dependencies=READ)
def get_delta(
    request: Request, name: str = Query(...), snapshot: str | None = None, tile: str | None = None
) -> Response:
    if name not in TIERS:
        raise HTTPException(404, detail=f"unknown tier {name}")
    if name in TILED and tile is None:
        raise HTTPException(400, detail=f"{name} is tiled: tile is required")
    markers_dir, sidestore = _dirs(request)
    marker = _run(request, snapshot)
    key = _ready(marker)
    with leased(request, [key]):
        if name in TILED:
            _tile(sidestore, key, timeline.chain(markers_dir), tile)
        rows = read.delta_rows(
            sidestore, DELTA_OF[name], key, table=name, tile=tile if name in TILED else None
        )
        body = {
            "name": name,
            "snapshot": key,
            "parent": marker.get("parent"),
            "tile": tile if name in TILED else None,
            "rows": [
                {
                    "uid": r["uid"],
                    "op": r["op"],
                    "before": json.loads(r["before"]) if r["before"] else None,
                    "after": json.loads(r["after"]) if r["after"] else None,
                }
                for r in rows
            ],
        }
        return _json(request, body)


def _layout_tile(at: layout_read.Layout, tile: str | None, *, removed: bool = False) -> None:
    if tile is not None and not at.is_block(tile, removed=removed):
        raise HTTPException(404, detail=f"unknown tile {tile}")


@router.get("/layout", dependencies=READ)
def get_layout(request: Request, snapshot: str | None = None, tile: str | None = None) -> Response:
    _, sidestore = _dirs(request)
    key = int(_run(request, snapshot)["key"])
    with leased(request, [key]):
        at = layout_read.layout_at(sidestore, key)
        _layout_tile(at, tile)
        rows = sorted(at.rows(tile), key=lambda r: r["uid"])
        return _json(request, {"snapshot": key, "tile": tile, **_columnar(rows, SCHEMAS["layout"].names)})


@router.get("/layout-delta", dependencies=READ)
def get_layout_delta(request: Request, snapshot: str | None = None, tile: str | None = None) -> Response:
    _, sidestore = _dirs(request)
    key = int(_run(request, snapshot)["key"])
    with leased(request, [key]):
        # A block that leaves the layout at `key` is still a tile of its delta.
        at = layout_read.layout_at(sidestore, key)
        _layout_tile(at, tile, removed=True)
        rows = at.delta(layout_read.delta_at(sidestore, key), tile)
        return _json(request, {"snapshot": key, "tile": tile, **_columnar(rows, SCHEMAS["layout"].names)})


@router.get("/device", dependencies=READ)
def get_device(request: Request, uid: str = Query(...), snapshot: str | None = None) -> dict[str, Any]:
    markers_dir, sidestore = _dirs(request)
    marker = _run(request, snapshot)
    key = _ready(marker)
    with leased(request, [key]):
        devices = read.tier_at(sidestore, "render_t1", key, timeline.chain(markers_dir))
        if uid not in set(devices.column("uid").to_pylist()):
            raise HTTPException(404, detail=f"unknown device {uid}")
        if marker.get("state") == "cold":
            rows = read.device_delta(sidestore, key, uid)
            return {
                "uid": uid,
                "snapshot": key,
                "state": "cold",
                "categories": {},
                "contexts": [],
                "tunnels": [],
                "rows": rows,
            }
        from hst.map import tier3

        found = tier3.device(request.app.state.settings, uid, key)
        return {"uid": uid, "snapshot": key, "state": "warm", **found}


@router.get("/segment", dependencies=READ)
def get_segment(request: Request, uid: str = Query(...), snapshot: str | None = None) -> dict[str, Any]:
    """The tier 3 clients of one segment of `render_t2_segments` at the run, read from the graph."""
    markers_dir, sidestore = _dirs(request)
    marker = _run(request, snapshot)
    key = _ready(marker)
    with leased(request, [key]):
        chain = timeline.chain(markers_dir)
        # The segment uid names its device. The block of the device is the tile of the segments table.
        device_uid = uid.split("/segment/")[0]
        devices = read.tier_at(sidestore, "render_t1", key, chain).to_pylist()
        device = next((r for r in devices if r["uid"] == device_uid), None)
        if device is None or not device.get("block_uid"):
            raise HTTPException(404, detail=f"unknown segment {uid}")
        try:
            rows = read.tier_at(
                sidestore, "render_t2_segments", key, chain, str(device["block_uid"])
            ).to_pylist()
        except read.NotFound as exc:
            raise HTTPException(404, detail=str(exc)) from None
        found = next((r for r in rows if r["uid"] == uid), None)
        if found is None:
            raise HTTPException(404, detail=f"unknown segment {uid}")
        head = {
            "uid": uid,
            "device_uid": found["device_uid"],
            "snapshot": key,
            "prefix": found.get("prefix"),
            "vid": found.get("vid"),
            "name": found.get("name"),
        }
        if marker.get("state") == "cold":
            return {**head, "state": "cold", "clients": []}
        from hst.map import tier3

        clients = tier3.segment(
            request.app.state.settings, found["device_uid"], found.get("bridge_domain_uid"), key
        )
        return {**head, "state": "warm", "clients": clients}


def _warm(request: Request, snapshot: str | None) -> int:
    marker = _run(request, snapshot)
    if marker.get("state") == "cold":
        raise HTTPException(409, detail=f"run {marker['key']} is cold: replay it to read its interfaces")
    return int(marker["key"])


def _interface(request: Request, uid: str, key: int) -> dict[str, Any]:
    from hst.map import tier3

    facts = tier3.interface_facts(request.app.state.settings, uid, key)
    if facts is None:
        raise HTTPException(404, detail=f"unknown interface {uid}")
    return facts


@router.get("/interface", dependencies=READ)
def get_interface(request: Request, uid: str = Query(...), snapshot: str | None = None) -> dict[str, Any]:
    key = _warm(request, snapshot)
    with leased(request, [key]):
        return {"snapshot": key, **_interface(request, uid, key)}


async def _known(request: Request) -> list[str]:
    """The credential values that the sources are configured with. The redaction
    removes them from the text of a configuration section (`core/redaction.py`).
    `runs_exec` loads the graph client and is imported in the function body."""
    from hst.app import runs_exec

    try:
        return await runs_exec.configured_secrets(request.app.state.store, request.app.state.settings)
    except Exception:
        raise HTTPException(
            503, detail="the sources' credentials could not be read, so the text was not redacted"
        ) from None


@router.get("/interface-text", dependencies=INTERFACES)
async def get_interface_text(
    request: Request, uid: str = Query(...), snapshot: str | None = None
) -> dict[str, Any]:
    """The interface's configuration section at the run, redacted."""
    from hst.app.crypto import dek
    from hst.core import redaction
    from hst.map import tier3

    def read() -> tuple[int, dict[str, Any] | None]:
        key = _warm(request, snapshot)
        facts = _interface(request, uid, key)
        settings = request.app.state.settings
        found = None
        if facts["device_uid"] and facts["name"]:
            try:
                found = tier3.interface_text(settings, dek(settings), facts["device_uid"], key, facts["name"])
            except FileNotFoundError:
                found = None
        return key, found

    key, found = await asyncio.to_thread(read)
    if found is None:
        raise HTTPException(404, detail=f"no interface configuration for {uid} at run {key}")
    known = await _known(request)
    return {"uid": uid, **found, "text": redaction.redact_known(found["text"], known)}


@router.get("/device-text", dependencies=INTERFACES)
async def get_device_text(
    request: Request, uid: str = Query(...), snapshot: str | None = None
) -> dict[str, Any]:
    """The device's version, routing, ACL and NAT configuration at the run, redacted."""
    from hst.app.crypto import dek
    from hst.core import redaction
    from hst.map import tier3

    def read() -> tuple[int, dict[str, Any] | None]:
        key = _warm(request, snapshot)
        settings = request.app.state.settings
        try:
            return key, tier3.device_text(settings, dek(settings), uid, key)
        except FileNotFoundError:
            return key, None

    key, found = await asyncio.to_thread(read)
    if found is None:
        raise HTTPException(404, detail=f"no configuration for {uid} at run {key}")
    known = await _known(request)
    sections = [
        {**s, "parts": [{**p, "text": redaction.redact_known(p["text"], known)} for p in s["parts"]]}
        for s in found["sections"]
    ]
    return {"uid": uid, "snapshot": key, **found, "sections": sections}


def _bus(request: Request) -> events.LocalBus:
    bus = getattr(request.app.state, "hst_bus", None)
    if bus is None:
        raise HTTPException(503, detail="the HST event bus is not running")
    return bus


def _since(last_event_id: str | None) -> tuple[int, int] | None:
    if not last_event_id:
        return None
    key, _, seq = last_event_id.partition(":")
    try:
        return int(key), int(seq)
    except ValueError:
        return None


@router.get("/events", dependencies=READ, response_class=EventSourceResponse)
async def get_events(
    request: Request,
    bus: events.LocalBus = Depends(_bus),
    last_event_id: str | None = Header(None, max_length=64),
) -> AsyncIterator[ServerSentEvent]:
    """`run.published` and `run.tiers_ready` as server-sent events, from `Last-Event-ID` on."""
    async for event in bus.subscribe(
        [events.RUN_PUBLISHED, events.RUN_TIERS_READY], since=_since(last_event_id)
    ):
        if await request.is_disconnected():
            break
        yield ServerSentEvent(id=f"{event.run_key}:{event.seq}", event=event.type, data=event.as_dict())
