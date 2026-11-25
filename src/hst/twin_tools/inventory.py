"""The inventory tools `inventory_search`, `inventory_get`, `inventory_list` and
`inventory_resolve`.

Every answer is a record lookup in one run. A record in the run is observed by
the collection of the run, or configured when it was carried forward. An object
that is missing from the result has no record in the run.
"""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel

from hst import path as pathmod
from hst.app.ai.registry import ToolContext, ToolError, ToolRegistry
from hst.core import db as dbmod
from hst.core.labels import LABELS
from hst.queries import RESOLVE_CONTEXT_QUERY
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    Call,
    ItemEvidence,
    catalogue_spec,
    jsonable,
    lookup_evidence,
    record_evidence,
)

# --- shared reads --------------------------------------------------------------------------

# The queries for every record of one address. Each query matches on the `ip`
# property (or `peer_ip` or `next_hop`). A uid from hst.core.uid.ip embeds an
# anchor, and one address exists as one IpAddress node per anchor.
ADDR_NODES_QUERY = """
MATCH (n:IpAddress:Obj)
WHERE NOT n:Retired AND n.collection_ts = $snap AND n.ip = $ip
RETURN n.uid AS uid, n.anchor AS anchor, n.l3dom AS l3dom, n.af AS af
ORDER BY n.uid LIMIT 11"""

ADDR_ENDPOINTS_QUERY = """
MATCH (e:Endpoint:Obj)-[h:HAS_IP]->(n:IpAddress)
WHERE NOT e:Retired AND NOT n:Retired AND h._retired_at IS NULL
  AND e.collection_ts = $snap AND n.ip = $ip
OPTIONAL MATCH (e)-[a:ATTACHED]->(att)
WHERE a._retired_at IS NULL AND NOT att:Retired
WITH e, n, [x IN collect(DISTINCT {uid: att.uid, name: att.name, ssid: a.ssid,
       kind: [l IN labels(att) WHERE l IN ['Port', 'Device']][0]}) WHERE x.uid IS NOT NULL] AS attached
OPTIONAL MATCH (e)-[i:IN]->(bd:BridgeDomain)
WHERE i._retired_at IS NULL AND NOT bd:Retired
WITH e, n, attached,
     [x IN collect(DISTINCT {uid: bd.uid, name: bd.name}) WHERE x.uid IS NOT NULL] AS bridge_domains
RETURN e.uid AS uid, e.mac AS mac, e.kind AS kind, e.name AS name,
       n.uid AS ip_uid, n.anchor AS anchor, attached, bridge_domains
ORDER BY uid LIMIT 11"""

ADDR_INTERFACES_QUERY = """
MATCH (i:Interface:Obj)-[h:HAS_IP]->(n:IpAddress)
WHERE NOT i:Retired AND NOT n:Retired AND h._retired_at IS NULL
  AND i.collection_ts = $snap AND n.ip = $ip
OPTIONAL MATCH (i)-[o:ON]->(d:Device)
WHERE o._retired_at IS NULL AND NOT d:Retired
RETURN i.uid AS uid, i.name AS name, i.kind AS kind, n.uid AS ip_uid, n.anchor AS anchor,
       d.uid AS device_uid, d.hostname AS device_hostname
ORDER BY uid LIMIT 11"""

ADDR_BGP_QUERY = """
MATCH (s:BgpSession:Obj)
WHERE NOT s:Retired AND s.collection_ts = $snap AND s.peer_ip = $ip
OPTIONAL MATCH (rp:RoutingProcess)-[hs:HAS]->(s)
WHERE hs._retired_at IS NULL AND NOT rp:Retired
OPTIONAL MATCH (rp)-[iv:IN_VRF]->(v:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT v:Retired
RETURN s.uid AS uid, s.peer_ip AS peer_ip, s.local_asn AS local_asn, s.peer_asn AS peer_asn,
       s.import_policy_name AS import_policy_name, s.import_policy_kind AS import_policy_kind,
       s.export_policy_name AS export_policy_name, s.export_policy_kind AS export_policy_kind,
       rp.uid AS process_uid, rp.proto AS process_proto, rp.asn AS process_asn,
       v.uid AS vrf_uid, v.name AS vrf_name
ORDER BY uid LIMIT 11"""

ADDR_NEXT_HOP_QUERY = """
MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)
WHERE NOT v:Retired AND NOT p:Retired AND r._retired_at IS NULL
  AND v.collection_ts = $snap AND r.next_hop = $ip
RETURN type(r) AS kind, p.cidr AS prefix, p.uid AS prefix_uid, r.protocol AS protocol,
       r.metric AS metric, r.interface AS interface, v.uid AS vrf_uid, v.name AS vrf_name
ORDER BY prefix, vrf_uid LIMIT 11"""

# The sections of one address, in the order an answer lists them.
ADDRESS_SECTIONS: tuple[tuple[str, str], ...] = (
    ("ip_nodes", ADDR_NODES_QUERY),
    ("endpoints", ADDR_ENDPOINTS_QUERY),
    ("interfaces", ADDR_INTERFACES_QUERY),
    ("bgp_sessions", ADDR_BGP_QUERY),
    ("next_hop_routes", ADDR_NEXT_HOP_QUERY),
)
_ADDRESS_QUERY_NAMES = (
    "ADDR_NODES_QUERY",
    "ADDR_ENDPOINTS_QUERY",
    "ADDR_INTERFACES_QUERY",
    "ADDR_BGP_QUERY",
    "ADDR_NEXT_HOP_QUERY",
)
# The count of rows that each section reports. Each query fetches one more
# row, and the extra row marks a cut section.
ADDRESS_SECTION_ROWS = 10


def address_sections(session: Any, address: str) -> dict[str, list[dict[str, Any]]]:
    """Every record of one address in the run `session` is pinned to, per
    section, with up to one row past `ADDRESS_SECTION_ROWS`.

    `address` is a normalized IP address. `session` is a session pinned with
    `path.pinned`, whose run every query binds as `$snap`.
    """
    return {name: pathmod._read(session, query, ip=address) for name, query in ADDRESS_SECTIONS}


_CARRIED_QUERY = """
MATCH (n:Obj) USING INDEX n:Obj(uid, collection_ts)
WHERE n.uid IN $uids AND n.collection_ts = $snap
RETURN n.uid AS uid, coalesce(n.carried, false) AS carried"""


def carried_flags(session: Any, uids: list[str]) -> dict[str, bool]:
    """Whether each record was carried forward into the run, by uid."""
    wanted = sorted({uid for uid in uids if uid})
    if not wanted:
        return {}
    return {row["uid"]: bool(row["carried"]) for row in pathmod._read(session, _CARRIED_QUERY, uids=wanted)}


def _with_evidence(
    rows: list[dict[str, Any]], carried: dict[str, bool], key: str = "uid"
) -> list[dict[str, Any]]:
    return [
        {**row, "evidence": record_evidence(carried.get(row.get(key) or "")).model_dump(mode="json")}
        for row in rows
    ]


_DEVICE_QUERY = """
MATCH (d:Device:Obj {uid: $uid, collection_ts: $snap})
WHERE NOT d:Retired
OPTIONAL MATCH (d)-[l:LOCATED_IN]->(s:Site)
WHERE l._retired_at IS NULL AND NOT s:Retired
WITH d, [x IN collect(DISTINCT {uid: s.uid, code: s.code}) WHERE x.uid IS NOT NULL] AS sites
OPTIONAL MATCH (d)-[m:MEMBER_OF]->(g:RedundancyGroup)
WHERE m._retired_at IS NULL AND NOT g:Retired
WITH d, sites, [x IN collect(DISTINCT g.uid) WHERE x IS NOT NULL] AS groups
OPTIONAL MATCH (i:Interface)-[o:ON]->(d)
WHERE o._retired_at IS NULL AND NOT i:Retired
OPTIONAL MATCH (i)-[iv:IN_VRF]->(v:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT v:Retired
WITH d, sites, groups, count(DISTINCT i) AS interface_count,
     collect(DISTINCT {uid: v.uid, name: v.name}) AS interface_vrfs
OPTIONAL MATCH (ov:VrfInstance)-[ob:OWNED_BY]->(d)
WHERE ob._retired_at IS NULL AND NOT ov:Retired
WITH d, sites, groups, interface_count,
     interface_vrfs + collect(DISTINCT {uid: ov.uid, name: ov.name}) AS vrfs
RETURN d.uid AS uid, d.hostname AS hostname, d.role AS role, d.vendor AS vendor,
       d.platform AS platform, d.serial AS serial, coalesce(d.carried, false) AS carried,
       sites, groups, interface_count, [x IN vrfs WHERE x.uid IS NOT NULL] AS vrfs"""


_DEVICE_UID_QUERY = """
MATCH (d:Device:Obj {uid: $uid, collection_ts: $snap})
WHERE NOT d:Retired
RETURN d.uid AS uid"""


def _resolve_device(pinned: Any, ref: str) -> str:
    """The uid of the device that `ref` names. `ref` is a device uid, else an
    exact hostname, else a hostname prefix. More than one match raises
    `ambiguous` with the candidates. No match raises `not_found`."""
    from hst.app.agent.tools import _match_devices

    if pathmod._read(pinned, _DEVICE_UID_QUERY, uid=ref):
        return ref
    matches = _match_devices(pinned, ref)
    if not matches:
        raise ToolError("not_found", f"no device {ref!r} in this snapshot", field="device")
    if len(matches) > 1:
        raise ToolError(
            "ambiguous",
            f"{len(matches) if len(matches) <= 10 else 'more than 10'} devices match {ref!r}; "
            "pass one uid from candidates",
            field="device",
            candidates=[{"uid": m["uid"], "hostname": m["hostname"]} for m in matches[:10]],
        )
    return str(matches[0]["uid"])


# --- inventory_search ----------------------------------------------------------------------


class InventorySearchInput(selectors.PagedInput):
    """Search one run for objects by uid, address or name."""

    q: str = Field(
        min_length=1, max_length=200, description="A uid, an IP address or prefix, or words of a name."
    )
    label: str | None = Field(
        default=None, max_length=64, description="Only objects with this graph label, e.g. Device."
    )


class SearchItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    uid: str
    label: str | None
    name: str | None = None
    match: Literal["uid", "address", "text"]
    detail: Any = None
    evidence: ItemEvidence


class SearchResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    query: str
    items: list[SearchItem]


def inventory_search(ctx: ToolContext, params: InventorySearchInput) -> str:
    from hst.app.routes import explore

    text = params.q.strip()
    if not text:
        raise ToolError("invalid_argument", "q holds no text to search for", field="q")
    if params.label is not None and params.label not in LABELS:
        raise ToolError("invalid_argument", f"unknown label {params.label!r}", field="label")
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "inventory_search", params, session)
        hits = explore.search_hits(ctx.settings, selectors.snap_binding(call.snapshot), text, params.label)
        carried = carried_flags(pathmod.pinned(session, call.snapshot), [h["uid"] for h in hits])
        items = [
            {
                "uid": h["uid"],
                "label": h.get("label"),
                "name": h.get("name"),
                "match": h.get("matched"),
                "detail": h.get("detail"),
                "evidence": record_evidence(carried.get(h["uid"])).model_dump(mode="json"),
            }
            for h in jsonable(hits)
        ]
        page_items, page = call.pager.take(items[call.pager.offset :], total=len(items))
        return call.finish(
            session,
            result={"query": text, "items": page_items},
            evidence=lookup_evidence(len(items)),
            page=page,
            engine_function="hst.app.routes.explore.search_hits",
        )


# --- inventory_get -------------------------------------------------------------------------


class DeviceGetInput(selectors.ToolInput):
    """One device and what it connects to."""

    kind: Literal["device"]
    device: selectors.DeviceRef
    include_collection: bool = Field(
        default=False,
        description="Add the inventory collection state of the device. Needs the runs.manage permission.",
    )


class SiteGetInput(selectors.PagedInput):
    """One site with its devices and connected prefixes, or the list of sites."""

    kind: Literal["site"]
    code: str | None = Field(
        default=None,
        max_length=64,
        description="The site code. Omitted, the sites of the run are listed.",
    )


class InventoryGetInput(RootModel[Annotated[DeviceGetInput | SiteGetInput, Field(discriminator="kind")]]):
    """kind: device reads one device; kind: site reads one site, or lists the sites."""


class InventoryGetResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: Literal["device", "site"]
    device: dict[str, Any] | None = None
    sites: list[dict[str, Any]] | None = None


_SITE_QUERY = """
MATCH (s:Site:Obj {uid: $uid})
WHERE NOT s:Retired AND (s:Meta OR s.collection_ts = $snap)
RETURN s.uid AS uid, s.code AS code, s.name AS name, s.kind AS kind,
       coalesce(s.carried, false) AS carried"""

_SITE_MEMBERS_QUERY = """
MATCH (d:Device)-[l:LOCATED_IN]->(s:Site:Obj {uid: $uid, collection_ts: $snap})
WHERE NOT d:Retired AND l._retired_at IS NULL AND d.collection_ts = $snap
RETURN d.uid AS uid ORDER BY uid"""

_SITES_QUERY = """
MATCH (s:Site:Obj)
WHERE NOT s:Retired AND (s:Meta OR s.collection_ts = $snap)
OPTIONAL MATCH (d:Device)-[l:LOCATED_IN]->(s)
WHERE NOT d:Retired AND l._retired_at IS NULL AND d.collection_ts = $snap
RETURN s.uid AS uid, s.code AS code, s.name AS name, s.kind AS kind,
       coalesce(s.carried, false) AS carried, count(DISTINCT d) AS device_count
ORDER BY coalesce(s.code, s.uid)"""

# Connected prefixes one site answer lists.
SITE_PREFIX_CAP = 500


def _device(ctx: ToolContext, params: DeviceGetInput) -> str:
    if params.include_collection and (
        ctx.principal is None or "runs.manage" not in ctx.principal.permissions
    ):
        raise ToolError(
            "permission_denied",
            "include_collection requires the runs.manage permission",
            field="include_collection",
        )
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "inventory_get", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        uid = _resolve_device(pinned, params.device)
        rows = pathmod._read(pinned, _DEVICE_QUERY, uid=uid)
        if not rows:
            raise ToolError("not_found", f"no device {params.device!r} in this snapshot", field="device")
        row = jsonable(rows[0])
        vrfs = list({v["uid"]: v for v in row.pop("vrfs")}.values())
        sites = row.pop("sites")
        groups = row.pop("groups")
        device = {
            **row,
            "site": sites[0]["code"] if sites else None,
            "site_uid": sites[0]["uid"] if sites else None,
            "redundancy_groups": groups,
            "vrfs": sorted(vrfs, key=lambda v: str(v["uid"]))[:200],
            "vrfs_truncated": len(vrfs) > 200,
            "collection": None,
            "evidence": record_evidence(row["carried"]).model_dump(mode="json"),
        }
        warnings = []
        if params.include_collection:
            device["collection"] = ctx.call_async(_collection(ctx, uid))
            if device["collection"] is None:
                warnings.append("the inventory holds no device for this graph uid")
        return call.finish(
            session,
            result={"kind": "device", "device": device},
            evidence=lookup_evidence(1),
            engine_function="hst.twin_tools.inventory.inventory_get",
            queries=[("fixed", "hst.twin_tools.inventory._DEVICE_QUERY")],
            warnings=warnings,
        )


async def _collection(ctx: ToolContext, graph_uid: str) -> list[dict[str, Any]] | None:
    """The collection summaries of the inventory device behind `graph_uid`, as
    the device detail route reports them to `runs.manage`. None when the store
    has no inventory, or no inventory device has the uid."""
    from hst.app.inventory import collection as inventory_collection
    from hst.app.inventory.inventory_routes import _collection_summaries
    from hst.app.inventory.observations import InventoryContext, ReadModel

    store = ctx.store
    owned = store is None
    if store is None:
        from hst.app.store.pg import PgStore

        store = PgStore(ctx.settings.postgres_dsn, ctx.settings.postgres_ca_file)
    try:
        if not inventory_collection.has_inventory(store):
            return None
        inventory = InventoryContext(store, ctx.settings)
        async with inventory.repo.transaction() as tx:
            device = await tx.get_device_by_graph_uid(graph_uid)
            if device is None:
                return None
            site_rows = await inventory.site_rows(tx).list()
            claims = await ReadModel(inventory).gather(tx, device, site_ids={s.code: s.id for s in site_rows})
            return [s.model_dump(mode="json") for s in await _collection_summaries(inventory, tx, claims)]
    finally:
        if owned:
            await store.dispose()


def _site(ctx: ToolContext, params: SiteGetInput) -> str:
    from hst.app.routes import sites as sites_route
    from hst.core import uid as uidmod

    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "inventory_get", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        if params.code is None:
            rows = [
                {**row, "evidence": record_evidence(row["carried"]).model_dump(mode="json")}
                for row in jsonable(pathmod._read(pinned, _SITES_QUERY))
            ]
            page_rows, page = call.pager.take(rows[call.pager.offset :], total=len(rows))
            return call.finish(
                session,
                result={"kind": "site", "sites": page_rows},
                evidence=lookup_evidence(len(rows)),
                page=page,
                queries=[("fixed", "hst.twin_tools.inventory._SITES_QUERY")],
            )
        uid = uidmod.site(params.code)
        found = pathmod._read(pinned, _SITE_QUERY, uid=uid)
        if not found:
            raise ToolError("not_found", f"no site {params.code!r} in this snapshot", field="code")
        members = [str(r["uid"]) for r in pathmod._read(pinned, _SITE_MEMBERS_QUERY, uid=uid)]
        # the device rows are built for at most one page of members, and the
        # page budget is measured on those rows
        start, end = call.pager.offset, call.pager.offset + call.pager.limit
        window = members[start:end]
        rows = _with_evidence(
            jsonable(sites_route.device_details(session, call.snapshot, window)),
            carried_flags(pinned, window),
        )
        devices, page = call.pager.take(rows, total=len(members), more=end < len(members))
        prefixes = sites_route.site_prefixes(session, call.snapshot, params.code)
        site = {
            **jsonable(found[0]),
            "device_count": len(members),
            "devices": devices,
            "connected_prefixes": prefixes[:SITE_PREFIX_CAP],
            "prefixes_truncated": len(prefixes) > SITE_PREFIX_CAP,
        }
        site["evidence"] = record_evidence(site["carried"]).model_dump(mode="json")
        return call.finish(
            session,
            result={"kind": "site", "sites": [site]},
            evidence=lookup_evidence(1),
            page=page,
            engine_function="hst.app.routes.sites.device_details",
            queries=[
                ("fixed", "hst.twin_tools.inventory._SITE_MEMBERS_QUERY"),
                ("fixed", "hst.app.routes.sites.site_prefixes"),
            ],
        )


def inventory_get(ctx: ToolContext, params: DeviceGetInput | SiteGetInput) -> str:
    if isinstance(params, DeviceGetInput):
        return _device(ctx, params)
    return _site(ctx, params)


# --- inventory_list ------------------------------------------------------------------------


class InterfacesListInput(selectors.PagedInput):
    """The interfaces of one device."""

    kind: Literal["interfaces"]
    device: selectors.DeviceRef
    name: str | None = Field(default=None, max_length=200, description="Only the interface with this name.")
    vrf: str | None = Field(
        default=None, max_length=512, description="Only interfaces in this VRF, by uid or name."
    )


class ZonesListInput(selectors.PagedInput):
    """Security zones, filtered by device, interface, rulebase and name."""

    kind: Literal["zones"]
    device: str | None = Field(
        default=None,
        max_length=512,
        description="Zones owned by this device, or holding one of its interfaces.",
    )
    interface: str | None = Field(
        default=None, max_length=512, description="Zones that contain this interface uid."
    )
    rulebase: str | None = Field(
        default=None, max_length=512, description="Zones a rulebase uid binds, from or to."
    )
    name: str | None = Field(default=None, max_length=200, description="Zones with this name.")


class InventoryListInput(
    RootModel[Annotated[InterfacesListInput | ZonesListInput, Field(discriminator="kind")]]
):
    """kind: interfaces lists a device's interfaces; kind: zones lists security zones."""


class InventoryListResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: Literal["interfaces", "zones"]
    device_uid: str | None = None
    items: list[dict[str, Any]]


_INTERFACES_QUERY = """
MATCH (i:Interface)-[o:ON]->(d:Device:Obj {uid: $device, collection_ts: $snap})
WHERE NOT i:Retired AND o._retired_at IS NULL AND i.collection_ts = $snap
  AND ($name IS NULL OR toLower(i.name) = toLower($name))
OPTIONAL MATCH (i)-[iv:IN_VRF]->(v:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT v:Retired
WITH i, v
WHERE $vrf IS NULL OR v.uid = $vrf OR toLower(v.name) = toLower($vrf)
OPTIONAL MATCH (z:Zone)-[c:CONTAINS]->(i)
WHERE c._retired_at IS NULL AND NOT z:Retired
WITH i, v, [x IN collect(DISTINCT z.uid) WHERE x IS NOT NULL] AS zones
OPTIONAL MATCH (i)-[h:HAS_IP]->(ip:IpAddress)
WHERE h._retired_at IS NULL AND NOT ip:Retired
OPTIONAL MATCH (ip)-[n:IN]->(p:Prefix)
WHERE n._retired_at IS NULL AND NOT p:Retired
WITH i, v, zones, [x IN collect(DISTINCT {ip: ip.ip, prefix: p.cidr}) WHERE x.ip IS NOT NULL] AS addresses
RETURN i.uid AS uid, i.name AS name, i.kind AS kind, i.mtu AS mtu,
       coalesce(i.oper_status, i.oper) AS oper_status, v.uid AS vrf_uid, v.name AS vrf,
       zones, addresses, coalesce(i.carried, false) AS carried
ORDER BY name, uid"""

_ZONES_QUERY = """
MATCH (z:Zone:Obj)
WHERE NOT z:Retired AND z.collection_ts = $snap
  AND ($name IS NULL OR toLower(z.name) = toLower($name))
OPTIONAL MATCH (z)-[ob:OWNED_BY]->(od:Device)
WHERE ob._retired_at IS NULL AND NOT od:Retired
WITH z, [x IN collect(DISTINCT od.uid) WHERE x IS NOT NULL] AS owners
OPTIONAL MATCH (z)-[c:CONTAINS]->(i:Interface)
WHERE c._retired_at IS NULL AND NOT i:Retired
OPTIONAL MATCH (i)-[o:ON]->(idev:Device)
WHERE o._retired_at IS NULL AND NOT idev:Retired
WITH z, owners, [x IN collect(DISTINCT i.uid) WHERE x IS NOT NULL] AS interfaces,
     [x IN collect(DISTINCT idev.uid) WHERE x IS NOT NULL] AS interface_devices
WHERE ($device IS NULL OR $device IN owners OR $device IN interface_devices)
  AND ($interface IS NULL OR $interface IN interfaces)
OPTIONAL MATCH (rb:FwRulebase)-[fz:FROM_ZONE|TO_ZONE]->(z)
WHERE fz._retired_at IS NULL AND NOT rb:Retired
WITH z, owners, interfaces,
     [x IN collect(DISTINCT {uid: rb.uid, side: CASE type(fz) WHEN 'FROM_ZONE' THEN 'from' ELSE 'to' END})
      WHERE x.uid IS NOT NULL] AS rulebases
WHERE $rulebase IS NULL OR any(r IN rulebases WHERE r.uid = $rulebase)
RETURN z.uid AS uid, z.name AS name, owners[0] AS owner_device, owners,
       z.default_action AS default_action, z.default_action_unknown AS default_action_unknown,
       interfaces, rulebases, coalesce(z.carried, false) AS carried
ORDER BY uid"""

# The caps of the nested lists of one item.
_ADDRESSES_CAP = 50
_ZONE_INTERFACES_CAP = 200
_ZONE_RULEBASES_CAP = 100


def _capped(row: dict[str, Any], key: str, cap: int) -> None:
    values = row.get(key) or []
    row[key] = values[:cap]
    row[f"{key}_truncated"] = len(values) > cap


def inventory_list(ctx: ToolContext, params: InterfacesListInput | ZonesListInput) -> str:
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "inventory_list", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        device_uid = None if params.device is None else _resolve_device(pinned, params.device)
        if isinstance(params, InterfacesListInput):
            rows = jsonable(
                pathmod._read(pinned, _INTERFACES_QUERY, device=device_uid, name=params.name, vrf=params.vrf)
            )
            for row in rows:
                _capped(row, "addresses", _ADDRESSES_CAP)
            query = "hst.twin_tools.inventory._INTERFACES_QUERY"
        else:
            rows = jsonable(
                pathmod._read(
                    pinned,
                    _ZONES_QUERY,
                    device=device_uid,
                    interface=params.interface,
                    rulebase=params.rulebase,
                    name=params.name,
                )
            )
            for row in rows:
                _capped(row, "interfaces", _ZONE_INTERFACES_CAP)
                _capped(row, "rulebases", _ZONE_RULEBASES_CAP)
            query = "hst.twin_tools.inventory._ZONES_QUERY"
        items = [{**row, "evidence": record_evidence(row["carried"]).model_dump(mode="json")} for row in rows]
        page_items, page = call.pager.take(items[call.pager.offset :], total=len(items))
        unknowns = []
        if isinstance(params, ZonesListInput):
            unknowns.append("an empty interface list is not evidence that a zone is a local zone")
        return call.finish(
            session,
            result={"kind": params.kind, "device_uid": device_uid, "items": page_items},
            evidence=lookup_evidence(len(items), unknowns),
            page=page,
            queries=[("fixed", query)],
        )


# --- inventory_resolve ---------------------------------------------------------------------


class ContextResolveInput(selectors.PagedInput):
    """Forwarding contexts (VrfInstance) by name."""

    kind: Literal["context"]
    name: str = Field(
        min_length=1, max_length=200, description="The context name, matched case-insensitively."
    )
    domain: str | None = Field(
        default=None,
        max_length=200,
        description="Only contexts that are members of a routing domain with this name.",
    )


class AddressResolveInput(selectors.ToolInput):
    """Every record of one IP address."""

    kind: Literal["address"]
    address: str = Field(max_length=64, description="An IPv4 or IPv6 address.")


class InventoryResolveInput(
    RootModel[Annotated[ContextResolveInput | AddressResolveInput, Field(discriminator="kind")]]
):
    """kind: context turns a name into VrfInstance uids; kind: address lists every record of an address."""


class InventoryResolveResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: Literal["context", "address"]
    items: list[dict[str, Any]] | None = None
    address: str | None = None
    sections: dict[str, dict[str, Any]] | None = None


def _context(ctx: ToolContext, params: ContextResolveInput) -> str:
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "inventory_resolve", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        rows = jsonable(pathmod._read(pinned, RESOLVE_CONTEXT_QUERY, name=params.name, domain=params.domain))
        items = _with_evidence(rows, carried_flags(pinned, [r["uid"] for r in rows]))
        page_items, page = call.pager.take(items[call.pager.offset :], total=len(items))
        unknowns = []
        if len(items) > 1:
            unknowns.append(f"the name matches {len(items)} contexts; choose one by uid")
        return call.finish(
            session,
            result={"kind": "context", "items": page_items},
            evidence=lookup_evidence(len(items), unknowns),
            page=page,
            engine_function="hst.queries.resolve_context",
            queries=[("fixed", "hst.queries.RESOLVE_CONTEXT_QUERY")],
        )


def _address(ctx: ToolContext, params: AddressResolveInput) -> str:
    try:
        address = str(ipaddress.ip_address(params.address.strip()))
    except ValueError as exc:
        raise ToolError(
            "invalid_argument", f"{params.address!r} is not an IP address: {exc}", field="address"
        ) from None
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "inventory_resolve", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        found = {name: jsonable(rows) for name, rows in address_sections(pinned, address).items()}
        uids = [
            row.get("vrf_uid" if name == "next_hop_routes" else "uid")
            for name, rows in found.items()
            for row in rows
        ]
        carried = carried_flags(pinned, [u for u in uids if u])
        sections: dict[str, dict[str, Any]] = {
            name: {
                "rows": _with_evidence(
                    rows[:ADDRESS_SECTION_ROWS],
                    carried,
                    key="vrf_uid" if name == "next_hop_routes" else "uid",
                ),
                "truncated": len(rows) > ADDRESS_SECTION_ROWS,
            }
            for name, rows in found.items()
        }
        count = sum(len(section["rows"]) for section in sections.values())
        return call.finish(
            session,
            result={"kind": "address", "address": address, "sections": sections},
            evidence=lookup_evidence(count),
            engine_function="hst.twin_tools.inventory.address_sections",
            queries=[("fixed", f"hst.twin_tools.inventory.{name}") for name in _ADDRESS_QUERY_NAMES],
        )


def inventory_resolve(ctx: ToolContext, params: ContextResolveInput | AddressResolveInput) -> str:
    if isinstance(params, ContextResolveInput):
        return _context(ctx, params)
    return _address(ctx, params)


def register(registry: ToolRegistry) -> None:
    registry.register(
        catalogue_spec(
            name="inventory_search",
            description=(
                "Search one run for objects: an exact uid first, then an exact IP address or prefix, "
                "then words of a name, hostname or description. Each item says how it matched. An "
                "object missing from the result has no record in the run, which is not evidence that "
                "it does not exist."
            ),
            input_model=InventorySearchInput,
            result_model=SearchResult,
            run=inventory_search,
        )
    )
    registry.register(
        catalogue_spec(
            name="inventory_get",
            description=(
                "Read one object of the run. kind: device takes a device uid or hostname and returns "
                "its role, vendor, platform, serial, site, redundancy groups, VRFs and interface count; "
                "include_collection adds its inventory collection state and needs runs.manage. "
                "kind: site takes a site code and returns its devices a page at a time and its "
                "connected prefixes; without a code it lists the sites."
            ),
            input_model=InventoryGetInput,
            result_model=InventoryGetResult,
            run=inventory_get,
        )
    )
    registry.register(
        catalogue_spec(
            name="inventory_list",
            description=(
                "List records of the run. kind: interfaces lists one device's interfaces with VRF, "
                "zones and addresses, filtered by name or VRF. kind: zones lists security zones with "
                "their owner, interfaces and the rulebases that bind them, filtered by device, "
                "interface uid, rulebase uid or name."
            ),
            input_model=InventoryListInput,
            result_model=InventoryListResult,
            run=inventory_list,
        )
    )
    registry.register(
        catalogue_spec(
            name="inventory_resolve",
            description=(
                "Resolve a name or an address to records of the run. kind: context turns a VRF name "
                "into VrfInstance uids with their routing domains and devices; more than one item means "
                "the name is ambiguous and the caller chooses by uid. kind: address lists every record "
                "of one IP address in five sections (IP nodes, endpoints, interfaces, BGP sessions, "
                "next-hop routes), 10 rows each. A next-hop is not a BGP peer."
            ),
            input_model=InventoryResolveInput,
            result_model=InventoryResolveResult,
            run=inventory_resolve,
        )
    )
