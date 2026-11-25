"""POST /api/changesim/export returns one policy simulation as a downloadable archive."""

from __future__ import annotations

import asyncio
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from hst import path as pathmod
from hst.app import changesim_export, fw_overlay_read
from hst.app.auth import require_permission
from hst.app.routes.run_lease import aleased
from hst.core import bgpsource, ospfsource, ribsource
from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import snapshot as snapshotmod
from hst.simul.fw_overlay import ProposalError

router = APIRouter()
_session = dbmod.session  # Tests replace this name.

# The bounds of the schema of the `change_simulate` tool (twin_tools/change.py).
MAX_INTENTS = 50
MAX_FLOWS = 50
MAX_SITES = 20


class ExportFlowMtu(BaseModel):
    """The same MTU request `GET /api/path` and the `reach_trace` tool take,
    minus `reply_ip_packet_bytes`. `hst.core.mtu.MtuRequest.model_validate`
    checks the range and the address-family and mode consistency where the
    flow reaches the engine (`fw_overlay_read._trace_flow`)."""

    mode: Literal["off", "inventory", "unfragmented", "packet"] = "off"
    ip_packet_bytes: int | None = None
    ipv4_df: bool | None = None
    traffic_class: str | None = None


class ExportFlow(BaseModel):
    src: str
    dst: str
    port: int | None = None
    proto: str | None = None
    mtu: ExportFlowMtu | None = None


class ExportBody(BaseModel):
    """The input of one simulation."""

    intents: list[dict[str, Any]] = Field(min_length=1, max_length=MAX_INTENTS)
    # The engine derives a bounded set from the change set when `flows` is omitted or empty.
    flows: list[ExportFlow] | None = Field(default=None, max_length=MAX_FLOWS)
    depth: int | None = Field(default=None, ge=1, le=fw_overlay_read._MAX_WITHDRAWAL_DEPTH)
    sites: list[str] | None = Field(default=None, max_length=MAX_SITES)


@router.post("/changesim/export", dependencies=[Depends(require_permission("graph.read"))])
async def export_change_simulation(request: Request, body: ExportBody) -> Response:
    """Run the simulation and answer with the archive it renders to."""
    settings = request.app.state.settings
    flows = [f.model_dump(exclude_none=True) for f in body.flows] if body.flows else None
    # A map from source name to collector kind (`name` to `type` of
    # hst.app.store.Source). The collected-evidence check of interface.set_mtu reads
    # it (fw_overlay_read.read_catalog, fw_overlay._validate_interface_set_mtu).
    # `_sources` on a Device holds the configured row name.
    source_kinds = {row.name: row.type for row in await request.app.state.store.list_sources()}

    def resolve() -> snapshotmod.Snapshot:
        with _session(settings) as session:
            return snapshotmod.resolve(session, settings)

    def simulate(snap: snapshotmod.Snapshot) -> tuple[bytes, bool, dict[str, Any] | None]:
        with _session(settings) as session:
            pinned = pathmod.pinned(session, snap)
            try:
                simulation = fw_overlay_read.simulate_change(
                    pinned,
                    intents=body.intents,
                    flows=flows,
                    depth=body.depth,
                    sites=body.sites,
                    detail=True,
                    rib=ribsource.for_snapshot(snap),
                    bgp=bgpsource.for_snapshot(snap),
                    ospf=ospfsource.for_snapshot(snap),
                    source_kinds=source_kinds,
                )
            except ProposalError as exc:
                raise HTTPException(400, detail=str(exc)) from exc
            except ValueError as exc:
                # a stored value the engine could not read is a fault in the data
                # under simulation
                raise HTTPException(
                    422, detail=f"the change simulation could not read the snapshot: {exc}"
                ) from exc
            sources = changesim_export.sources_for(pinned, simulation.get("changed_devices") or [])
            status = cyclemod.run_status(session, snap)
        csv_text, markdown_text, trimmed = changesim_export.render(
            simulation, snapshot=snap.cts, sources=sources, sites_requested=body.sites
        )
        json_text = changesim_export.json_report(simulation)
        content = changesim_export.archive(csv_text, markdown_text, json_text, snapshot=snap.cts)
        return content, trimmed, status

    # The export resolves the snapshot once (core/snapshot.py). The graph pin, the
    # RIB bound and the run id in the file and in the headers come from that
    # snapshot. The graph reads, the simulation and the render run on a worker thread.
    snap = await asyncio.to_thread(resolve)
    cts = snap.cts
    async with aleased(request, [cts]):
        content, trimmed, status = await asyncio.to_thread(simulate, snap)
    name = changesim_export.basename(cts)
    return Response(
        content=content,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{name}.zip"',
            # the pane compares this with the run it shows
            "X-HST-Snapshot": "" if cts is None else str(cts),
            "X-HST-Export-Trimmed": "true" if trimmed else "false",
            "X-HST-Degraded": "true" if status and status.get("degraded") else "false",
        },
    )
