"""GET /api/path runs the flow tracer."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request

from hst import path as pathmod
from hst.app.auth import require_permission
from hst.app.routes.run_lease import leased
from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import ribsource
from hst.core import snapshot as snapshotmod
from hst.core.mtu import MtuRequest
from hst.path.gates.firewall import _as_portset, _as_protoset
from hst.results.trace import project_trace

router = APIRouter()
_session = dbmod.session  # Tests replace this name.


def _requested_run(s: Any, value: str | None) -> int | None:
    """The run id a request's `snapshot` parameter names, checked against the graph.

    None when the parameter is omitted, and the caller resolves the pointer.
    A value that is not a run id is a 400. A run id whose graph is not
    retained is a 404, raised before any engine read, in the shape of the
    diff route's unknown-run answer.
    """
    try:
        cts = snapshotmod.parse_snapshot_id(value)
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    if cts is not None:
        try:
            snapshotmod.require_retained(s, cts)
        except ValueError as exc:
            raise HTTPException(404, detail=f"unknown run: {cts}") from exc
    return cts


def _parse_port(raw: str | None) -> int | str | None:
    """The `port` query param as `trace()` takes it. A bare number is an int.
    Any other value is the range spec string (`"any"`, `"0-65535"`, `"80,443"`,
    `"1-1024"`).
    """
    if not raw:
        return None
    return int(raw) if raw.isdigit() else raw


def _parse_proto(raw: str | None) -> str | list[str] | frozenset[int] | None:
    """The `proto` query param as `trace()` takes it. One token stays a string
    unless it names more than one protocol. Then the result is the set of the
    protocols. A comma list becomes the list of its members."""
    if not raw:
        return None
    members = [p.strip() for p in raw.split(",") if p.strip()]
    if not members:
        return None
    if len(members) > 1:
        _as_protoset(members)
        return members
    token = members[0]
    resolved = _as_protoset(token)[0]
    if resolved is None or len(resolved) == 1:
        return token
    return resolved


@router.get("/path", dependencies=[Depends(require_permission("graph.read"))])
def get_path(
    request: Request,
    src: str,
    dst: str,
    port: str | None = None,
    proto: str | None = None,
    src_context: str | None = None,
    dst_context: str | None = None,
    start_table: str | None = None,
    start_vrf: str | None = None,
    snapshot: str | None = None,
    snapshot_b: str | None = None,
    reply: bool = False,
    mtu_mode: Literal["off", "inventory", "unfragmented", "packet"] = "off",
    mtu_ip_packet_bytes: int | None = None,
    mtu_ipv4_df: bool | None = None,
    mtu_reply_ip_packet_bytes: int | None = None,
    mtu_traffic_class: str | None = None,
    dscp: int | None = None,
) -> dict:
    try:
        mtu = MtuRequest.model_validate(
            {
                "mode": mtu_mode,
                "ip_packet_bytes": mtu_ip_packet_bytes,
                "ipv4_df": mtu_ipv4_df,
                "reply_ip_packet_bytes": mtu_reply_ip_packet_bytes,
                "traffic_class": mtu_traffic_class,
            }
        )
        if mtu.reply_ip_packet_bytes is not None and not reply:
            raise ValueError("mtu_reply_ip_packet_bytes requires reply=true")
        port_val = _parse_port(port)
        proto_val = _parse_proto(proto)
        _as_portset(port_val)
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    if reply and snapshot_b:
        raise HTTPException(400, detail="reply and snapshot_b cannot both be set")
    if start_vrf and (start_table or src_context):
        raise HTTPException(400, detail="start_vrf cannot be set with start_table or src_context")
    settings = request.app.state.settings
    # The runs whose `:CycleRun` node existed when the request resolved them. A
    # prune deletes that node before the objects of the run. A run in this set
    # whose node is gone was pruned, and an answer read from it is partial.
    present: set[int] = set()

    def run_trace(s, snap: snapshotmod.Snapshot) -> dict:
        def pruned() -> HTTPException:
            return HTTPException(409, detail=f"run {snap.cts} was pruned while the trace ran")

        if snap.cts in present and cyclemod.run_status(s, snap) is None:
            raise pruned()
        kwargs: dict[str, Any] = {}
        if reply:
            kwargs["reply"] = True
        if mtu.mode != "off":
            kwargs["mtu"] = mtu
        if start_table:
            kwargs["start_table"] = start_table
        if dscp is not None:
            kwargs["dscp"] = dscp
        try:
            if start_vrf:
                # `start_vrf` is a VRF name. The engine picks the device that the trace starts on
                # (path.vrf_starts).
                result = pathmod.trace_from_vrf(
                    pathmod.pinned(s, snap),
                    src,
                    dst,
                    start_vrf,
                    port=port_val,
                    proto=proto_val,
                    rib=ribsource.for_snapshot(snap),
                    dst_context=dst_context,
                    **kwargs,
                )
            else:
                result = pathmod.trace(
                    pathmod.pinned(s, snap),
                    src,
                    dst,
                    port=port_val,
                    proto=proto_val,
                    rib=ribsource.for_snapshot(snap),
                    src_context=src_context,
                    dst_context=dst_context,
                    **kwargs,
                )
        except ValueError as exc:
            # A caller error that the engine reports is a 400 with the reason of the
            # engine. Examples are an unreadable port or protocol spec, and a reply
            # asked of a source that resolves to more than one interpretation.
            raise HTTPException(400, detail=str(exc)) from exc
        # the run this answer was computed from, with its degraded, carried or
        # failed sources
        status = cyclemod.run_status(s, snap)
        if snap.cts in present and status is None:
            raise pruned()
        return {**project_trace(result), "run": status}

    with _session(settings) as s:
        # The request resolves each snapshot once (core/snapshot.py). The graph pin,
        # the side-store bound and the run in the answer come from it. Each side of
        # a compare is its own run and its own snapshot.
        if snapshot_b:
            # An absent `snapshot` is the current run. The composer sends only
            # snapshot_b when the A side is the current run.
            a = snapshotmod.resolve(s, settings, _requested_run(s, snapshot))
            if a.cts is None:
                raise HTTPException(400, detail="no runs exist yet to compare against")
            b = snapshotmod.resolve(s, settings, _requested_run(s, snapshot_b))
            snaps = [a, b]
        else:
            snaps = [snapshotmod.resolve(s, settings, _requested_run(s, snapshot))]
        present.update(
            snap.cts for snap in snaps if snap.cts is not None and cyclemod.run_status(s, snap) is not None
        )
    # The runs are leased before the first read and checked again inside the
    # lease. A prune that began before the lease decided without it.
    with leased(request, [snap.cts for snap in snaps if snap.cts is not None]), _session(settings) as s:
        if snapshot_b:
            return {
                "a": {"snapshot": snaps[0].snapshot_id, "result": run_trace(s, snaps[0])},
                "b": {"snapshot": snapshot_b, "result": run_trace(s, snaps[1])},
            }
        return run_trace(s, snaps[0])


@router.get("/path/vrfs", dependencies=[Depends(require_permission("graph.read"))])
def get_path_vrfs(request: Request, snapshot: str | None = None) -> dict:
    """Every VRF name of one run, once, with the number of devices that have
    it. `GET /path` accepts these names as `start_vrf`. The trace composer
    fills its start VRF picker from them."""
    settings = request.app.state.settings
    with _session(settings) as s:
        snap = snapshotmod.resolve(s, settings, _requested_run(s, snapshot))
        return {"vrfs": pathmod.start_vrfs(pathmod.pinned(s, snap))}
