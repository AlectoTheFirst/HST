"""The load balancer lookup tool `lb_lookup_vip`.

`direction: vip_to_members` lists the virtual services whose VIP is an
address, each with the members of the pools it uses. `direction:
member_to_vips` lists the virtual services whose pools hold a member that
targets an address, the reverse of the same path:
`(VirtualService)-[:USES]->(Pool)-[:HAS_MEMBER]->(PoolMember)-[:TARGETS]->(IpAddress)`.
The members of each virtual service come from `_POOL_MEMBERS_QUERY`, the
read of the load balancer gate of the path engine. Each member has the health
state that the collector recorded.

The gate evaluates the kinds lb, alb, nlb, azlb and appgw. A content-switching
(cs) or GSLB virtual service dispatches by policy. The gate does not evaluate
the policy, and the item is not established. An item of any other kind that
the gate does not evaluate is not established. An item of an evaluated kind is
a proven record.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hst import path as pathmod
from hst.app.ai.registry import ToolContext, ToolError, ToolRegistry
from hst.core import db as dbmod
from hst.results.words import record
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    Call,
    Evidence,
    ItemEvidence,
    Missing,
    catalogue_spec,
    gap_list,
    jsonable,
    lookup_evidence,
    record_evidence,
    whole_result,
)

# Virtual services one call reads, and members one item lists.
MAX_SERVICES = 1000
MAX_MEMBERS = 200
KIND_GAP = "LB_KIND_NOT_EVALUATED"
_KIND_GAP_DETAIL = "the virtual service is of a kind the engine does not evaluate"

_BY_VIP = """
MATCH (vs:VirtualService:Obj)-[ev:VIP]->(vip:IpAddress {ip: $ip})
WHERE NOT vs:Retired AND ev._retired_at IS NULL AND vs.collection_ts = $snap
  AND NOT vip:Retired AND vip.collection_ts = $snap
WITH DISTINCT vs, [] AS matched_members
"""

_BY_MEMBER = """
MATCH (pm:PoolMember:Obj)-[et:TARGETS]->(ip:IpAddress {ip: $ip})
WHERE NOT pm:Retired AND et._retired_at IS NULL AND pm.collection_ts = $snap
  AND NOT ip:Retired AND ip.collection_ts = $snap
MATCH (pool:Pool)-[eh:HAS_MEMBER]->(pm)
WHERE NOT pool:Retired AND eh._retired_at IS NULL AND pool.collection_ts = $snap
MATCH (vs:VirtualService)-[eu:USES]->(pool)
WHERE NOT vs:Retired AND eu._retired_at IS NULL AND vs.collection_ts = $snap
WITH vs, collect(DISTINCT {uid: pm.uid, port: pm.port, state: pm.state}) AS matched_members
"""

# Reads the virtual service with its VIPs, its ON target, its SNAT address and
# the services that a content-switching virtual service dispatches to.
_SERVICE = """
OPTIONAL MATCH (vs)-[ev2:VIP]->(v:IpAddress:Obj)
WHERE ev2._retired_at IS NULL AND NOT v:Retired AND v.collection_ts = $snap
OPTIONAL MATCH (vs)-[eon:ON]->(target)
WHERE eon._retired_at IS NULL AND NOT target:Retired
OPTIONAL MATCH (vs)-[es:SNAT_FROM]->(snip:IpAddress)
WHERE es._retired_at IS NULL AND NOT snip:Retired AND snip.collection_ts = $snap
OPTIONAL MATCH (vs)-[ed:DISPATCHES]->(next:VirtualService)
WHERE ed._retired_at IS NULL AND NOT next:Retired AND next.collection_ts = $snap
RETURN vs.uid AS uid, vs.name AS name, vs.kind AS kind, vs.proto AS proto, vs.port AS port,
       vs.state AS state, vs.snat_mode AS snat_mode, coalesce(vs.carried, false) AS carried,
       [x IN collect(DISTINCT v.ip) WHERE x IS NOT NULL] AS vips,
       [x IN collect(DISTINCT target.uid) WHERE x IS NOT NULL] AS on_targets,
       [x IN collect(DISTINCT snip.ip) WHERE x IS NOT NULL] AS snat_from,
       [x IN collect(DISTINCT next.uid) WHERE x IS NOT NULL] AS dispatches,
       matched_members
ORDER BY uid LIMIT 1001"""


class LbLookupInput(selectors.PagedInput):
    """Virtual services by VIP, or by the address one of their members targets."""

    address: str = Field(max_length=64, description="An IPv4 or IPv6 address.")
    direction: Literal["vip_to_members", "member_to_vips"] = Field(
        description=(
            "vip_to_members lists the virtual services whose VIP is the address, with their members. "
            "member_to_vips lists the virtual services with a pool member that targets the address."
        )
    )
    port: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        description=(
            "vip_to_members: only virtual services whose port covers this port. member_to_vips: only "
            "members whose port covers it. A service or member that states no port covers every port."
        ),
    )


class LbLookupResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    address: str
    direction: str
    items: list[dict[str, Any]] = Field(
        description=(
            "per virtual service on this page: its uid, VIPs, port, kind, what it is on, its pools and "
            "members with their recorded state, and evidence"
        )
    )


def _item(row: dict[str, Any], members: list[dict[str, Any]]) -> dict[str, Any]:
    pools = list(
        dict.fromkeys(
            (member.get("pool_uid"), member.get("pool_name")) for member in members if member.get("pool_uid")
        )
    )
    matched = {member["uid"] for member in row.get("matched_members") or ()}
    return {
        "virtual_service": row["uid"],
        "name": row.get("name"),
        "vip": (row.get("vips") or [None])[0],
        "vips": row.get("vips") or [],
        "port": row.get("port"),
        "proto": row.get("proto"),
        "kind": row.get("kind"),
        "state": row.get("state"),
        "on_device": row["on_targets"][0] if len(row.get("on_targets") or ()) == 1 else None,
        "on": row.get("on_targets") or [],
        "pool": pools[0][0] if pools else None,
        "pools": [{"uid": uid, "name": name} for uid, name in pools],
        "snat_mode": row.get("snat_mode"),
        "snat_from": (row.get("snat_from") or [None])[0],
        "dispatches": row.get("dispatches") or [],
        "members": [
            {
                "uid": member["uid"],
                "name": member.get("name"),
                "ip": member.get("ip"),
                "port": member.get("port"),
                "state": member.get("state"),
                "pool": member.get("pool_uid"),
                **({"matched": member["uid"] in matched} if matched else {}),
            }
            for member in members[:MAX_MEMBERS]
        ],
        "member_count": len(members),
        "members_truncated": len(members) > MAX_MEMBERS,
        "evidence": _item_evidence(row).model_dump(mode="json"),
    }


def _item_evidence(row: dict[str, Any]) -> ItemEvidence:
    """The evidence of a virtual service as a record. The record is observed or
    carried forward when the load balancer gate evaluates its kind. Otherwise
    the record is `kind-not-evaluated`."""
    from hst.path.gates.lb import _vip_supported

    if _vip_supported(row):
        return record_evidence(row.get("carried"))
    return ItemEvidence.of(
        record(
            "kind-not-evaluated",
            missing=[Missing(code=KIND_GAP, subject=str(row["uid"]), detail=_KIND_GAP_DETAIL)],
        ),
        basis="configured",
    )


def lb_lookup_vip(ctx: ToolContext, params: LbLookupInput) -> str:
    from hst.path.addrsets import _MATCH, _port_matches
    from hst.path.gates.lb import _pool_members, _vip_supported

    try:
        address = str(ipaddress.ip_address(params.address.strip()))
    except ValueError as exc:
        raise ToolError(
            "invalid_argument", f"{params.address!r} is not an IP address: {exc}", field="address"
        ) from None
    head = _BY_VIP if params.direction == "vip_to_members" else _BY_MEMBER
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "lb_lookup_vip", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        rows = jsonable(pathmod._read(pinned, head + _SERVICE, ip=address))
        unknowns = [
            "member health is the state the collector recorded; a member with no state has no bound monitor",
            "which member a virtual service chooses for a flow is not evaluated; reach_trace evaluates the "
            "load balancer along a path",
        ]
        if len(rows) > MAX_SERVICES:
            rows = rows[:MAX_SERVICES]
            unknowns.append(f"only the first {MAX_SERVICES} virtual services are listed")
        if params.port is not None:
            if params.direction == "vip_to_members":
                rows = [row for row in rows if _port_matches(row.get("port"), params.port) == _MATCH]
            else:
                for row in rows:
                    row["matched_members"] = [
                        member
                        for member in row.get("matched_members") or ()
                        if _port_matches(member.get("port"), params.port) == _MATCH
                    ]
                rows = [row for row in rows if row["matched_members"]]
        offset = call.pager.offset
        window = [
            _item(row, jsonable(_pool_members(pinned, row["uid"])))
            for row in rows[offset : offset + params.limit]
        ]
        taken, page = call.pager.take(window, total=len(rows), more=len(rows) > offset + params.limit)
        skipped = [row for row in rows if not _vip_supported(row)]
        if skipped:
            unknowns.append(
                "virtual services of kind "
                + ", ".join(sorted({str(row.get("kind")) for row in skipped}))
                + " dispatch by policy, or are of a kind the load balancer gate does not evaluate; which "
                "members serve them is not established"
            )
        if rows:
            gaps, gaps_truncated = gap_list(
                {"code": KIND_GAP, "kind": "not-modeled", "subject": row["uid"]} for row in skipped
            )
            evidence = Evidence(
                result=whole_result((_item_evidence(row).result for row in rows), unknowns=unknowns),
                gaps=gaps,
                gaps_truncated=gaps_truncated,
                unknowns=unknowns,
                absence="not_recorded",
            )
        else:
            evidence = lookup_evidence(0, unknowns)
        return call.finish(
            session,
            result={"address": address, "direction": params.direction, "port": params.port, "items": taken},
            evidence=evidence,
            page=page,
            engine="hst.path.gates.lb",
            engine_function="hst.path.gates.lb._pool_members",
            queries=[("fixed", "hst.path.gates.lb._POOL_MEMBERS_QUERY")],
        )


def register(registry: ToolRegistry) -> None:
    registry.register(
        catalogue_spec(
            name="lb_lookup_vip",
            description=(
                "Load balancer virtual services of one run by address. direction vip_to_members lists "
                "the virtual services whose VIP is the address, with the members of their pools and the "
                "health state the collector recorded; member_to_vips lists the virtual services with a "
                "pool member that targets the address. Each item gives the VIP, port, kind, the device or "
                "group it is on, the SNAT address and the members. Content-switching (cs) and GSLB virtual "
                "services dispatch by policy and are not established. port keeps services, or members, "
                "whose port covers it. Items page with the cursor."
            ),
            input_model=LbLookupInput,
            result_model=LbLookupResult,
            run=lb_lookup_vip,
        )
    )
