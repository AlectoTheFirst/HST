"""The lookup tools and graph reads of the generator.

`search_objects` finds the objects of one kind by name. `resolve_hostname`
lists the records that hold a hostname and the IpAddress nodes they reach.
`object_addresses` follows fixed chains from one object to the IpAddress or
Prefix nodes that give it an address. `policy_route_sources` lists the policy
route rules that send traffic to a tunnel, an egress interface or a routing
table. Each rule has the addresses that it matches after the earlier rules of
its policy. The tool reads the rule rows that the PBR stage of the trace reads
(`path.gates.pbr.POLICY_RULES`) and partitions them with the same first-match
function (`partition_rules`). The addresses of an address object come from
`path.netobjects` and the interval helpers of the trace (`path.addrsets`).

`LABELS` maps a kind to a graph label. It holds the discovery kinds of
`discovery.KINDS` and the kinds through which an application member is found,
such as VIPs, VMs, endpoints and zones. The module does not change
`discovery.KINDS`. `CHAIN_LABELS` holds the labels that `object_addresses`
resolves to IpAddress or Prefix nodes.

The tools are offered on the `service_generator` surface only and take no
`snapshot` argument. Each call reads the run that the generation pinned
(`ToolContext.snapshot`). Every node and relationship that a chain reads has
the `collection_ts` of that run. `GraphFacts` holds the reads of the
post-processor at the same run.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from hst import path as pathmod
from hst.app.ai.registry import (
    AGENT_MODEL_CHARS,
    Surface,
    ToolContext,
    ToolError,
    ToolLimits,
    ToolSpec,
    invalid_argument,
)
from hst.applications.models import InventoryReference
from hst.applications.resolution import GraphInventoryReader, InventoryCandidate
from hst.assessment import discovery
from hst.core import db as dbmod
from hst.core import snapshot as snapshotmod
from hst.core.reasoner import RT_IMPORTED_ROUTES
from hst.path import netobjects
from hst.path.addrsets import _complement, _intersect, _merge, _rule_intervals
from hst.path.gates import pbr as pbrmod
from hst.path.netobjects import _alive, _current
from hst.path.netobjects import address as _address
from hst.path.netobjects import net_objects as _net_objects
from hst.path.netobjects import networks as _networks
from hst.path.netobjects import range_intervals as _range_intervals
from hst.path.netobjects import side_intervals as _side_intervals
from hst.path.netobjects import source_entries as _source_entries
from hst.path.netobjects import target_intervals as _target_intervals
from hst.path.netobjects import target_label as _target_label
from hst.twin_tools.inventory import ADDR_NODES_QUERY

GENERATOR_SURFACES: frozenset[Surface] = frozenset({"service_generator"})
# MAX_ROWS is the most rows that one answer lists. LIMITS bounds the model copy
# of one call.
MAX_ROWS = 100
LIMITS = ToolLimits(timeout_s=60.0, max_model_chars=AGENT_MODEL_CHARS)

SearchKind = Literal[
    "service",
    "device",
    "interface",
    "rulebase",
    "link",
    "tunnel",
    "domain",
    "network",
    "ip",
    "dns",
    "vip",
    "pool",
    "vm",
    "endpoint",
    "zone",
    "site",
    "vrf",
    "segment",
    "identity",
    "business_service",
    "app_component",
    "pbr_policy",
    "net_object",
]

# The graph label of each kind. The discovery kinds come first, then the kinds
# that only the generator searches.
LABELS: Mapping[str, str] = {
    **discovery.KINDS,
    "network": "Prefix",
    "ip": "IpAddress",
    "dns": "DnsRecord",
    "vip": "VirtualService",
    "pool": "Pool",
    "vm": "Vm",
    "endpoint": "Endpoint",
    "zone": "Zone",
    "site": "Site",
    "vrf": "VrfInstance",
    "segment": "ZpaAppSegment",
    "identity": "IdentityGroup",
    "business_service": "BusinessService",
    "app_component": "AppComponent",
    "pbr_policy": "PbrPolicy",
    "net_object": "NetObject",
}

# A chain edge as a map. The keys are quoted because FROM and TO are Cypher
# keywords.
_EDGE = "{{`from`: {a}.uid, rel: '{rel}', `to`: {b}.uid}}"


def _edge(a: str, rel: str, b: str) -> str:
    return _EDGE.format(a=a, rel=rel, b=b)


_PATH_EDGES = (
    "[r IN coalesce(relationships(p), []) | {`from`: startNode(r).uid, rel: type(r), `to`: endNode(r).uid}]"
)
_PATH_ALIVE = (
    "all(x IN nodes(p) WHERE x.collection_ts = $snap AND NOT x:Retired) "
    "AND all(r IN relationships(p) WHERE r.collection_ts = $snap AND r._retired_at IS NULL)"
)

_NODE = """
MATCH (n:Obj {uid: $uid, collection_ts: $snap})
WHERE NOT n:Retired
RETURN labels(n) AS labels, coalesce(n.name, n.hostname, n.fqdn, n.code, n.uid) AS name,
       coalesce(n.ip, n.cidr) AS address
LIMIT 1"""

_DEVICE_ROLE = """
MATCH (d:Device:Obj {uid: $uid, collection_ts: $snap})
WHERE NOT d:Retired
RETURN d.role AS role
LIMIT 1"""

_VIP = f"""
MATCH (vs:VirtualService:Obj {{uid: $uid, collection_ts: $snap}})-[r:VIP]->(ip:IpAddress)
WHERE {_alive("vs", "ip")} AND {_current("r")}
RETURN ip.uid AS uid, 'IpAddress' AS label, ip.ip AS address, 'vip' AS role,
       [{_edge("vs", "VIP", "ip")}] AS chain
ORDER BY uid LIMIT 101"""

_POOL_MEMBERS = f"""
MATCH (vs:VirtualService:Obj {{uid: $uid, collection_ts: $snap}})-[r1:USES]->(pool:Pool)
      -[r2:HAS_MEMBER]->(pm:PoolMember)
      -[r3:TARGETS]->(ip:IpAddress)
WHERE {_alive("vs", "pool", "pm", "ip")} AND {_current("r1", "r2", "r3")}
RETURN ip.uid AS uid, 'IpAddress' AS label, ip.ip AS address, 'pool-member' AS role, pm.port AS port,
       [{_edge("vs", "USES", "pool")}, {_edge("pool", "HAS_MEMBER", "pm")},
        {_edge("pm", "TARGETS", "ip")}] AS chain
ORDER BY uid LIMIT 101"""

# The addresses of the device a virtual service is on, or of the member
# devices of the redundancy group it is on. An owner with no address gives one
# row with a null uid, and that row reports the ON edge.
_OWNER = f"""
MATCH (vs:VirtualService:Obj {{uid: $uid, collection_ts: $snap}})-[r1:ON]->(owner)
WHERE {_alive("vs", "owner")} AND {_current("r1")}
OPTIONAL MATCH p = (owner)<-[:MEMBER_OF*0..1]-(:Device)<-[:ON]-(:Interface)-[:HAS_IP]->(ip:IpAddress)
WHERE {_PATH_ALIVE}
RETURN ip.uid AS uid, 'IpAddress' AS label, ip.ip AS address, 'owner-interface' AS role,
       [{_edge("vs", "ON", "owner")}] + {_PATH_EDGES} AS chain
ORDER BY uid LIMIT 101"""

_VM = f"""
MATCH (vm:Vm:Obj {{uid: $uid, collection_ts: $snap}})<-[r1:OF]-(nic:Vnic)-[r2:HAS_IP]->(ip:IpAddress)
WHERE {_alive("vm", "nic", "ip")} AND {_current("r1", "r2")}
RETURN ip.uid AS uid, 'IpAddress' AS label, ip.ip AS address, 'vnic' AS role,
       [{_edge("nic", "OF", "vm")}, {_edge("nic", "HAS_IP", "ip")}] AS chain
ORDER BY uid LIMIT 101"""

_HOST = f"""
MATCH (h:Obj {{uid: $uid, collection_ts: $snap}})-[r:HAS_IP]->(ip:IpAddress)
WHERE {_alive("h", "ip")} AND {_current("r")}
RETURN ip.uid AS uid, 'IpAddress' AS label, ip.ip AS address, 'host' AS role,
       [{_edge("h", "HAS_IP", "ip")}] AS chain
ORDER BY uid LIMIT 101"""

DNS_ANSWERS = f"""
MATCH p = (d:DnsRecord:Obj {{uid: $uid, collection_ts: $snap}})-[:RESOLVES_TO*1..8]->(ip:IpAddress)
WHERE {_PATH_ALIVE}
RETURN DISTINCT ip.uid AS uid, 'IpAddress' AS label, ip.ip AS address, 'dns-answer' AS role,
       {_PATH_EDGES} AS chain
ORDER BY uid LIMIT 101"""

# The connected networks of a zone. They are the prefixes of the addresses of
# its interfaces.
_ZONE = f"""
MATCH (z:Zone:Obj {{uid: $uid, collection_ts: $snap}})-[r1:CONTAINS]->(i:Interface)
      -[r2:HAS_IP]->(ip:IpAddress)-[r3:IN]->(pfx:Prefix)
WHERE {_alive("z", "i", "ip", "pfx")} AND {_current("r1", "r2", "r3")}
RETURN DISTINCT pfx.uid AS uid, 'Prefix' AS label, pfx.cidr AS address, 'zone-network' AS role,
       [{_edge("z", "CONTAINS", "i")}, {_edge("i", "HAS_IP", "ip")}, {_edge("ip", "IN", "pfx")}] AS chain
ORDER BY uid LIMIT 101"""

# The addresses of the members of an application component. A member gives its
# own address, or a member VM gives the address of its Vnic.
_COMPONENT = f"""
MATCH (c:AppComponent:Obj {{uid: $uid, collection_ts: $snap}})<-[r1:PART_OF]-(m)
WHERE {_alive("c", "m")} AND {_current("r1")}
OPTIONAL MATCH p = (m)<-[:OF*0..1]-()-[:HAS_IP]->(ip:IpAddress)
WHERE {_PATH_ALIVE}
RETURN ip.uid AS uid, 'IpAddress' AS label, ip.ip AS address, 'component-member' AS role,
       [{_edge("m", "PART_OF", "c")}] + {_PATH_EDGES} AS chain
ORDER BY uid LIMIT 101"""

_TUNNEL_INTERFACES = f"""
MATCH (t:Tunnel:Obj {{uid: $uid, collection_ts: $snap}})-[e:ENDPOINT]->(i:Interface)
WHERE {_alive("t", "i")} AND {_current("e")}
RETURN i.uid AS uid, i.name AS name
ORDER BY uid LIMIT 101"""

# The routes of every routing table that leave through one of the interfaces
# `$ifs`. A route is `(VrfInstance)-[:STATIC_ROUTE|LEARNED_ROUTE]->(Prefix)-[:VIA]->(Interface)`.
# The query skips the derived rt-import edges and reads the imported routes
# through `RT_IMPORTED_ROUTES`.
_INTERFACE_ROUTES = f"""
CALL {{
  MATCH (v:VrfInstance)-[r:STATIC_ROUTE|LEARNED_ROUTE]->(p:Prefix)-[via:VIA]->(i:Interface:Obj)
  WHERE i.uid IN $ifs AND coalesce(via.vrf, v.uid) = v.uid
    AND {_alive("v", "p", "i")} AND {_current("r", "via")}
    AND coalesce(r.derived, '') <> 'rt-import'
  RETURN v, p, i, r.next_hop AS next_hop
  UNION ALL
  MATCH (p:Prefix)-[pvia:VIA]->(pi:Interface:Obj)
  WHERE pi.uid IN $ifs AND {_alive("p", "pi")} AND {_current("pvia")}
  WITH DISTINCT p
  {RT_IMPORTED_ROUTES}
  WITH v, p WHERE {_alive("v")}
  MATCH (p)-[via:VIA]->(i:Interface:Obj)
  WHERE i.uid IN $ifs AND coalesce(via.vrf, v.uid) = v.uid AND {_alive("i")} AND {_current("via")}
  RETURN v, p, i, null AS next_hop
}}
RETURN v.uid AS table_uid, v.name AS table_name, p.cidr AS cidr, i.uid AS if_uid, i.name AS if_name,
       next_hop
ORDER BY table_uid, cidr, if_uid LIMIT 201"""

_TABLE_ROUTES = f"""
CALL {{
  MATCH (v:VrfInstance:Obj {{uid: $uid, collection_ts: $snap}})-[r:STATIC_ROUTE|LEARNED_ROUTE]->(p:Prefix)
  WHERE {_alive("v", "p")} AND {_current("r")} AND coalesce(r.derived, '') <> 'rt-import'
  RETURN v, p, r.next_hop AS next_hop
  UNION ALL
  MATCH (v:VrfInstance:Obj {{uid: $uid, collection_ts: $snap}})
  WHERE {_alive("v")}
  {RT_IMPORTED_ROUTES}
  RETURN v, p, null AS next_hop
}}
OPTIONAL MATCH (p)-[via:VIA]->(i:Interface)
WHERE coalesce(via.vrf, v.uid) = v.uid AND {_alive("i")} AND {_current("via")}
RETURN v.uid AS table_uid, v.name AS table_name, p.cidr AS cidr, i.uid AS if_uid, i.name AS if_name,
       next_hop
ORDER BY cidr, if_uid LIMIT 201"""

# The policies that hold an enabled rule which sends traffic to one of the
# tables `$tables`.
_REDIRECTING_POLICIES = f"""
MATCH (pol:PbrPolicy)-[hr:HAS_RULE]->(r:FwRule)-[rv:REDIRECTS_VIA]->(v:VrfInstance:Obj)
WHERE v.uid IN $tables AND r.enabled AND {_alive("pol", "r", "v")} AND {_current("hr", "rv")}
RETURN DISTINCT pol.uid AS uid
ORDER BY uid LIMIT 51"""

# The device that holds each policy and the ingress interfaces it is bound to.
_POLICY_BINDINGS = f"""
MATCH (pol:PbrPolicy:Obj)
WHERE pol.uid IN $pol_uids AND {_alive("pol")}
OPTIONAL MATCH (i:Interface)-[e:ENFORCES]->(pol)
WHERE {_alive("i")} AND {_current("e")}
WITH pol, [x IN collect(DISTINCT {{uid: i.uid, name: i.name}}) WHERE x.uid IS NOT NULL] AS interfaces
OPTIONAL MATCH (d:Device)-[de:ENFORCES]->(pol)
WHERE {_alive("d")} AND {_current("de")}
RETURN pol.uid AS uid, pol.name AS name, interfaces,
       [x IN collect(DISTINCT {{uid: d.uid, name: coalesce(d.hostname, d.name, d.uid)}})
        WHERE x.uid IS NOT NULL] AS devices
ORDER BY uid"""

# The labels that `object_addresses` resolves, in the order of precedence for a
# node with several of them. `_CHAINS` holds the chain reads of each label. A
# NetObject is read through `path.netobjects.net_objects`.
CHAIN_LABELS: tuple[str, ...] = (
    "IpAddress",
    "Prefix",
    "VirtualService",
    "Vm",
    "Endpoint",
    "Zone",
    "DnsRecord",
    "AppComponent",
    "NetObject",
)
_CHAINS: Mapping[str, tuple[str, ...]] = {
    "VirtualService": (_VIP, _POOL_MEMBERS, _OWNER),
    "Vm": (_VM,),
    "Endpoint": (_HOST,),
    "Zone": (_ZONE,),
    "DnsRecord": (DNS_ANSWERS,),
    "AppComponent": (_COMPONENT,),
}


def _search_query(label: str) -> str:
    """Objects of one label whose name, hostname, code, FQDN, address or uid
    contains `$q`. `label` comes from `LABELS` only."""
    return f"""
MATCH (n:`{label}`:Obj)
WHERE n.collection_ts = $snap AND NOT n:Retired
  AND any(text IN [n.name, n.hostname, n.code, n.fqdn, n.cidr, n.ip, n.uid]
          WHERE text IS NOT NULL AND toLower(toString(text)) CONTAINS $q)
RETURN n.uid AS uid, coalesce(n.name, n.hostname, n.fqdn, n.code, n.uid) AS name,
       coalesce(n.ip, n.cidr) AS address
ORDER BY toLower(toString(coalesce(n.name, n.hostname, n.fqdn, n.code, n.uid))), n.uid
LIMIT $limit"""


def _validated[M: BaseModel](model: type[M], arguments: Mapping[str, Any]) -> M:
    try:
        return model.model_validate(dict(arguments))
    except ValidationError as exc:
        raise invalid_argument(exc) from None


def _pinned_run(ctx: ToolContext) -> snapshotmod.Snapshot:
    """Return the run that the generation pinned. Raises ToolError for a context without one."""
    if ctx.snapshot is None or ctx.snapshot.cts is None:
        raise ToolError("snapshot_not_found", "the generator tools read the run the generation pinned")
    return ctx.snapshot


class SearchObjectsInput(BaseModel):
    """Objects of one kind whose name, hostname, site code or uid contains the text."""

    model_config = ConfigDict(extra="forbid")

    kind: SearchKind = Field(
        description=(
            "network: Prefix, ip: IpAddress, dns: DnsRecord, vip: VirtualService, pool: Pool, vm: Vm, "
            "endpoint: Endpoint, zone: Zone, site: Site, vrf: VrfInstance, segment: ZpaAppSegment, "
            "identity: IdentityGroup, business_service: BusinessService, app_component: AppComponent, "
            "and the assessment kinds service, device, interface, rulebase, link, tunnel and domain."
        )
    )
    q: str = Field(min_length=1, max_length=200, description="Words of the name, hostname, site code or uid.")
    limit: int = Field(default=20, ge=1, le=50, description="The most objects returned.")


def search_objects(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    params = _validated(SearchObjectsInput, arguments)
    snap = _pinned_run(ctx)
    text = params.q.strip()
    if not text:
        raise ToolError("invalid_argument", "q holds no text to search for", field="q")
    label = LABELS[params.kind]
    items: list[dict[str, Any]]
    if params.kind in discovery.KINDS:
        found = discovery.search_options(ctx.settings, str(snap.cts), params.kind, text, limit=params.limit)
        items = [
            {
                "uid": item["uid"],
                "label": label,
                "kind": params.kind,
                "name": item.get("name"),
                "addresses": item.get("addresses") or [],
            }
            for item in found["items"]
        ]
        truncated = bool(found.get("truncated"))
    else:
        with dbmod.session(ctx.settings, access_mode="READ") as session:
            rows = pathmod._read(
                pathmod.pinned(session, snap), _search_query(label), q=text.casefold(), limit=params.limit + 1
            )
        truncated = len(rows) > params.limit
        items = [
            {
                "uid": row["uid"],
                "label": label,
                "kind": params.kind,
                "name": row.get("name"),
                "address": row.get("address"),
            }
            for row in rows[: params.limit]
        ]
    return {
        "snapshot": snap.snapshot_id,
        "kind": params.kind,
        "q": text,
        "items": items,
        "truncated": truncated,
    }


class ResolveHostnameInput(BaseModel):
    """The records that hold a hostname, and the IpAddress nodes they reach."""

    model_config = ConfigDict(extra="forbid")

    fqdn: str = Field(min_length=1, max_length=500, description="A hostname, an FQDN or a URL.")


def _chain_rows(session: Any, query: str, uid: str) -> list[dict[str, Any]]:
    return [
        {key: row.get(key) for key in ("uid", "label", "address", "role", "port", "chain") if key in row}
        for row in pathmod._read(session, query, uid=uid)
    ]


def resolve_hostname(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    from hst.assessment.service_discovery import _host_addresses, destination_clue

    params = _validated(ResolveHostnameInput, arguments)
    snap = _pinned_run(ctx)
    try:
        hostname, _address, _port, notes = destination_clue(params.fqdn)
    except ValueError as exc:
        raise ToolError("invalid_argument", str(exc), field="fqdn") from None
    if hostname is None:
        raise ToolError(
            "invalid_argument",
            f"{params.fqdn} is an address; use inventory_resolve with kind address",
            field="fqdn",
        )
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        pinned = pathmod.pinned(session, snap)
        _values, complete, choices = _host_addresses(pinned, hostname)
        records = []
        for choice in choices[:MAX_ROWS]:
            uid = str(choice["uid"])
            node = pathmod._read(pinned, _NODE, uid=uid)
            labels = list(node[0]["labels"]) if node else []
            query = DNS_ANSWERS if "DnsRecord" in labels else _HOST
            rows = _chain_rows(pinned, query, uid)
            records.append(
                {
                    "uid": uid,
                    "label": next((label for label in labels if label != "Obj"), None),
                    "addresses": choice.get("addresses") or [],
                    "ip_nodes": [row for row in rows if row.get("uid") is not None][:MAX_ROWS],
                }
            )
    return {
        "snapshot": snap.snapshot_id,
        "fqdn": hostname,
        "records": records,
        "complete": complete and len(choices) <= MAX_ROWS,
        "notes": notes,
    }


class ObjectAddressesInput(BaseModel):
    """The IpAddress or Prefix nodes one object reaches through a fixed chain."""

    model_config = ConfigDict(extra="forbid")

    uid: str = Field(
        min_length=1,
        max_length=500,
        description=(
            "The uid of a VirtualService, Vm, Endpoint, Zone, DnsRecord, AppComponent, NetObject "
            "(an address object or group), IpAddress or Prefix."
        ),
    )


def _net_object_answer(
    obj: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """The items, the ranges and the unresolved entries of one address object."""
    uid = str(obj["uid"])
    items: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    for target in obj.get("targets") or []:
        chain = [{"from": uid, "rel": "RESOLVES_TO", "to": target["uid"]}]
        label = _target_label(list(target.get("labels") or []))
        if label == "DnsRecord" or not _target_intervals(target):
            unresolved.append(
                {
                    "chain": chain,
                    "detail": f"{target['uid']} is a {label or 'node'} with no address of its own",
                }
            )
            continue
        items.append(
            {
                "uid": target["uid"],
                "label": label,
                "address": _address(str(target.get("ip") or target.get("cidr"))),
                "role": "object-member",
                "chain": chain,
            }
        )
    ranges = [
        {"range": spec, "networks": _networks(_range_intervals(spec))}
        for spec in obj.get("ranges") or []
        if isinstance(spec, str)
    ]
    if obj.get("opaque"):
        unresolved.append(
            {"chain": [], "detail": obj.get("opaque_reason") or "the collector could not express this object"}
        )
    return items, ranges, unresolved


def object_addresses(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    params = _validated(ObjectAddressesInput, arguments)
    snap = _pinned_run(ctx)
    ranges: list[dict[str, Any]] | None = None
    object_unresolved: list[dict[str, Any]] = []
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        pinned = pathmod.pinned(session, snap)
        found = pathmod._read(pinned, _NODE, uid=params.uid)
        if not found:
            raise ToolError("not_found", f"no object {params.uid} in this snapshot", field="uid")
        node = found[0]
        labels = list(node["labels"])
        label = next((name for name in CHAIN_LABELS if name in labels), None)
        if label is None:
            raise ToolError(
                "invalid_argument",
                f"{params.uid} is a {', '.join(x for x in labels if x != 'Obj')}; object_addresses follows "
                f"the chains of {', '.join(CHAIN_LABELS)}",
                field="uid",
            )
        if label in ("IpAddress", "Prefix"):
            rows = [
                {
                    "uid": params.uid,
                    "label": label,
                    "address": node.get("address"),
                    "role": "self",
                    "chain": [],
                }
            ]
        elif label == "NetObject":
            obj = _net_objects(pinned, [params.uid]).get(params.uid, {"uid": params.uid})
            rows, ranges, object_unresolved = _net_object_answer(obj)
        else:
            rows = [row for query in _CHAINS[label] for row in _chain_rows(pinned, query, params.uid)]
    items = [row for row in rows if row.get("uid") is not None]
    unresolved = object_unresolved + [
        {"chain": row.get("chain") or [], "detail": "no address is recorded along this chain"}
        for row in rows
        if row.get("uid") is None
    ]
    answer: dict[str, Any] = {
        "snapshot": snap.snapshot_id,
        "uid": params.uid,
        "label": label,
        "name": node.get("name"),
        "items": items[:MAX_ROWS],
        "truncated": len(items) > MAX_ROWS,
        "unresolved": unresolved[:MAX_ROWS],
    }
    if ranges is not None:
        # A range has no node. The generator writes the networks of a range as
        # literal addresses.
        answer["ranges"] = ranges[:MAX_ROWS]
    return answer


class PolicyRouteSourcesInput(BaseModel):
    """The policy route rules that send traffic to a tunnel, an interface, a
    routing table, or the rules of one policy route."""

    model_config = ConfigDict(extra="forbid")

    uid: str = Field(
        min_length=1,
        max_length=500,
        description=(
            "The uid of a Tunnel, an egress Interface, a routing table (VrfInstance) or a PbrPolicy."
        ),
    )


_Ivals = netobjects.Ivals
_SideObjects = netobjects.SideObjects


def _service(row: Mapping[str, Any]) -> list[dict[str, Any]] | str:
    """The protocols and ports a rule matches, or `any` when it names no service."""
    if not row.get("svc_obj_count"):
        return "any"
    members = [
        {"protocol": proto, "ports": ports}
        for proto, ports in zip(row.get("svc_protos") or [], row.get("svc_port_specs") or [], strict=False)
    ]
    if row.get("svc_opaque"):
        members.append({"unreadable": "; ".join(row.get("svc_opaque_reasons") or []) or "opaque service"})
    return members


def _match(intervals: _Ivals, objects: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "any": not intervals,
        "objects": [{"uid": obj["uid"], "name": obj.get("name")} for obj in objects],
        "addresses": _networks(intervals)[:MAX_ROWS],
    }


def _union(groups: list[dict[str, Any]], key: str) -> _Ivals:
    return _merge([interval for group in groups for interval in group[key]])


def _rule_summary(row: Mapping[str, Any], objects: _SideObjects) -> dict[str, Any]:
    uid = str(row["rule_uid"])
    return {
        "uid": uid,
        "position": row.get("pos"),
        "name": row.get("rule_name"),
        "table": {"uid": row.get("table_uid"), "name": row.get("table_name")},
        "source": _match(_side_intervals(row, "src"), objects.get(f"{uid}:SRC", [])),
        "destination": _match(_side_intervals(row, "dst"), objects.get(f"{uid}:DST", [])),
        "service": _service(row),
    }


def _policy_rules(
    session: Any,
    pol_uids: list[str],
    wanted: Callable[[Mapping[str, Any], _Ivals], _Ivals | None],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Return the rules of the policies `pol_uids` that `wanted` keeps, and the notes.

    Each rule has its policy, its match, the source and destination sets that
    it decides after the earlier rules of its policy, and the earlier rules
    that send part of its match elsewhere.

    `wanted(row, destinations)` returns the destination set to report for a
    rule, or None to leave the rule out. The partition uses the first-match
    function of the trace over the whole address space of the families that
    the rules of the policy name. The service dimension stays open, and a rule
    scoped to a protocol claims only that part."""
    rows = pathmod._read(session, pbrmod.POLICY_RULES, pol_uids=pol_uids)
    bindings = {str(row["uid"]): row for row in pathmod._read(session, _POLICY_BINDINGS, pol_uids=pol_uids)}
    objects = netobjects.rule_side_objects(
        session, [str(row["rule_uid"]) for row in rows if row.get("rule_uid")]
    )
    by_policy: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_policy.setdefault(str(row["pol_uid"]), []).append(row)
    out: list[dict[str, Any]] = []
    notes: list[str] = []
    for pol_uid, policy_rows in by_policy.items():
        rules = [row for row in policy_rows if row.get("rule_uid")]
        families = {
            interval[0] for row in rules for side in ("src", "dst") for interval in _side_intervals(row, side)
        } or {4, 6}
        universe = _complement([], families)
        groups = pbrmod.partition_rules(rules, universe, universe, None, service=(None, None, None))
        binding = bindings.get(pol_uid) or {}
        policy = {
            "uid": pol_uid,
            "name": binding.get("name") or policy_rows[0].get("pol_name"),
            "devices": sorted(binding.get("devices") or [], key=lambda item: str(item["uid"])),
            "interfaces": sorted(binding.get("interfaces") or [], key=lambda item: str(item["uid"])),
        }
        for index, row in enumerate(rules):
            uid = str(row["rule_uid"])
            claimed = [group for group in groups if group["rule_uid"] == uid]
            if not claimed:
                continue
            destinations = wanted(row, _union(claimed, "dst"))
            if destinations is None:
                continue
            sources = _union(claimed, "sources")
            summary = _rule_summary(row, objects)
            src_objects = objects.get(f"{uid}:SRC", [])
            entry: dict[str, Any] = {
                "policy": policy,
                "rule": summary,
                "sources": _source_entries(src_objects, sources, pol_uid, uid)[:MAX_ROWS],
                "source_networks": _networks(sources)[:MAX_ROWS],
                "destinations": _networks(destinations)[:MAX_ROWS],
                "earlier_rules": _earlier(rules[:index], row, universe, objects),
            }
            if src_objects and summary["source"]["any"]:
                notes.append(
                    f"rule {row.get('pos')} of {policy['name']} names source objects that carry no address "
                    "the trace reads, so it matches every source"
                )
            out.append(entry)
    return out, notes


def _earlier(
    before: Sequence[Mapping[str, Any]],
    row: Mapping[str, Any],
    universe: _Ivals,
    objects: _SideObjects,
) -> list[dict[str, Any]]:
    """The earlier rules of the policy that send part of what `row` matches to
    another table."""
    src = _side_intervals(row, "src") or universe
    dst = _side_intervals(row, "dst") or universe
    out = []
    for earlier in before:
        if earlier.get("table_uid") == row.get("table_uid"):
            continue
        if not _intersect(_side_intervals(earlier, "src") or universe, src):
            continue
        if not _intersect(_side_intervals(earlier, "dst") or universe, dst):
            continue
        out.append(_rule_summary(earlier, objects))
    return out[:MAX_ROWS]


def _route(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "cidr": row.get("cidr"),
        "interface": {"uid": row.get("if_uid"), "name": row.get("if_name")} if row.get("if_uid") else None,
        "next_hop": row.get("next_hop"),
    }


def _tables(rows: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    tables: dict[str, dict[str, Any]] = {}
    for row in rows[:200]:
        table = tables.setdefault(
            str(row["table_uid"]), {"uid": row["table_uid"], "name": row.get("table_name"), "routes": []}
        )
        table["routes"].append(_route(row))
    return tables


def policy_route_sources(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    params = _validated(PolicyRouteSourcesInput, arguments)
    snap = _pinned_run(ctx)
    notes: list[str] = []
    interfaces: list[dict[str, Any]] = []
    tables: dict[str, dict[str, Any]] = {}
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        pinned = pathmod.pinned(session, snap)
        found = pathmod._read(pinned, _NODE, uid=params.uid)
        if not found:
            raise ToolError("not_found", f"no object {params.uid} in this snapshot", field="uid")
        node = found[0]
        labels = list(node["labels"])
        label = next((x for x in ("Tunnel", "Interface", "VrfInstance", "PbrPolicy") if x in labels), None)
        if label is None:
            raise ToolError(
                "invalid_argument",
                f"{params.uid} is a {', '.join(x for x in labels if x != 'Obj')}; policy_route_sources "
                "reads a Tunnel, an Interface, a VrfInstance or a PbrPolicy",
                field="uid",
            )
        if label == "PbrPolicy":
            pol_uids = [params.uid]

            def wanted(row: Mapping[str, Any], destinations: _Ivals) -> _Ivals | None:
                return destinations

        else:
            # `covered` maps a table uid to the destinations that the table routes
            # through the target. The value is None for the table of the argument
            # `uid`, and every route of that table counts.
            covered: dict[str, _Ivals | None]
            if label == "VrfInstance":
                route_rows = pathmod._read(pinned, _TABLE_ROUTES, uid=params.uid)
                tables = _tables(route_rows) or {
                    params.uid: {"uid": params.uid, "name": node.get("name"), "routes": []}
                }
                covered = {params.uid: None}
            else:
                if label == "Tunnel":
                    interfaces = pathmod._read(pinned, _TUNNEL_INTERFACES, uid=params.uid)[:MAX_ROWS]
                    if not interfaces:
                        notes.append(f"{params.uid} records no tunnel interface (ENDPOINT)")
                else:
                    interfaces = [{"uid": params.uid, "name": node.get("name")}]
                route_rows = (
                    pathmod._read(pinned, _INTERFACE_ROUTES, ifs=[str(i["uid"]) for i in interfaces])
                    if interfaces
                    else []
                )
                tables = _tables(route_rows)
                covered = {
                    uid: _rule_intervals([route["cidr"] for route in table["routes"]], [], [])
                    for uid, table in tables.items()
                }
                if interfaces and not tables:
                    names = ", ".join(str(i.get("name") or i["uid"]) for i in interfaces)
                    notes.append(f"no route of any routing table leaves through {names}")

            def wanted(row: Mapping[str, Any], destinations: _Ivals) -> _Ivals | None:
                table = row.get("table_uid")
                if table not in covered:
                    return None
                limit = covered[table]
                if limit is None:
                    return destinations
                # the destinations the table routes through the interface
                inside = _intersect(destinations, limit)
                return inside or None

            pol_uids = (
                [
                    str(row["uid"])
                    for row in pathmod._read(pinned, _REDIRECTING_POLICIES, tables=list(covered))
                ]
                if covered
                else []
            )
        rules, rule_notes = _policy_rules(pinned, pol_uids, wanted) if pol_uids else ([], [])
    if (tables or label == "PbrPolicy") and not rules:
        notes.append("no enabled policy route rule sends traffic to it")
    return {
        "snapshot": snap.snapshot_id,
        "uid": params.uid,
        "label": label,
        "name": node.get("name"),
        "interfaces": interfaces,
        "tables": list(tables.values())[:MAX_ROWS],
        "rules": rules[:MAX_ROWS],
        "truncated": len(rules) > MAX_ROWS or len(pol_uids) > 50,
        "notes": notes + rule_notes,
    }


def _spec(
    name: str,
    description: str,
    input_model: type[BaseModel],
    run: Callable[[ToolContext, dict[str, Any]], Any],
) -> ToolSpec:
    return ToolSpec(
        name=name,
        version=1,
        description=description,
        input_model=input_model,
        permission="graph.read",
        kind="read",
        snapshot="graph",
        run=run,
        surfaces=GENERATOR_SURFACES,
        limits=LIMITS,
        idempotent=True,
    )


def specs() -> list[ToolSpec]:
    """The generator's own tools, in the order the generator offers them."""
    return [
        _spec(
            "search_objects",
            "Find objects of one kind in the generation's snapshot whose name, hostname, site code, "
            "address or uid contains q. Each item gives the uid, the graph label and the name. More than "
            "one item means the phrase matches several objects.",
            SearchObjectsInput,
            search_objects,
        ),
        _spec(
            "resolve_hostname",
            "List the DNS records and the hostname-bearing objects that record a hostname, each with the "
            "addresses it records and the IpAddress nodes it reaches, with the chain of edges to each.",
            ResolveHostnameInput,
            resolve_hostname,
        ),
        _spec(
            "object_addresses",
            "Follow the fixed chains from one object to the IpAddress or Prefix nodes that give it an "
            "address: a VirtualService to its VIP, its pool members and the device it is on; a Vm through "
            "its Vnics; an Endpoint; a Zone to the prefixes of its interfaces; a DnsRecord to its answers; "
            "an AppComponent through its members; a NetObject (an address object or group) to the "
            "addresses it carries, with each range as the smallest list of networks. Each item gives the "
            "node uid, its address, its role and the chain of edges.",
            ObjectAddressesInput,
            object_addresses,
        ),
        _spec(
            "policy_route_sources",
            "List the policy route (PBR) rules that send traffic to a tunnel, an egress interface or a "
            "routing table, or every rule of one PbrPolicy. For each rule: the policy, the device and the "
            "ingress interfaces it is bound to, the target table, the source and destination match, the "
            "concrete source addresses it decides after the earlier rules of its policy (an address with "
            "a uid is an IpAddress or Prefix node; an address without one is a network of a range), the "
            "destinations it sends to the target, and the earlier rules that take part of its match "
            "elsewhere. tables lists the routes through the target.",
            PolicyRouteSourcesInput,
            policy_route_sources,
        ),
    ]


class GraphFacts:
    """The post-processor's reads of the generation's run.

    `session` is a graph session pinned to the run with `path.pinned`.
    `snapshot` is the snapshot reference of the run.
    """

    def __init__(self, session: Any, snapshot: Mapping[str, Any]) -> None:
        self.session = session
        self.snapshot = dict(snapshot)
        self.reader = GraphInventoryReader(session, int(self.snapshot["snapshot"]))

    def resolve(self, reference: InventoryReference) -> list[InventoryCandidate]:
        """The objects an inventory reference names, as validation resolves them."""
        return self.reader.resolve(reference, self.snapshot)

    def ip_nodes(self, address: str) -> list[str]:
        """Return the uids of every IpAddress node recorded for `address`. A
        binding that is not one address, such as a prefix, gives an empty list."""
        try:
            value = str(ipaddress.ip_address(address))
        except ValueError:
            return []
        return [str(row["uid"]) for row in pathmod._read(self.session, ADDR_NODES_QUERY, ip=value)]

    def device_role(self, uid: str) -> str | None:
        """The role of the Device node `uid`, or None when the run holds no
        such device or it records no role."""
        rows = pathmod._read(self.session, _DEVICE_ROLE, uid=uid)
        role = rows[0].get("role") if rows else None
        return str(role) if role is not None else None

    def dns_answers(self, uid: str) -> list[tuple[str, str]]:
        """The IpAddress nodes a DnsRecord resolves to, as (uid, address)."""
        return [
            (str(row["uid"]), str(row["address"]))
            for row in pathmod._read(self.session, DNS_ANSWERS, uid=uid)
            if row.get("uid") is not None and row.get("address") is not None
        ]
