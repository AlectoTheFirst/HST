"""Per-device reads of one run for the tiers.

Every per-device query anchors on the `obj_uid_cts` constraint by
`(uid, collection_ts)` and traverses to same-run copies. The fold reads the devices a
delta touched. The bootstrap and the consistency run read every device. The
session is any object with `run(query, **params)`. The module imports no graph client.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from hst.core.labels import GATE_BINDINGS

from .schemas import COUNTS

BATCH = 500

DEVICES = """
MATCH (d:Device:Obj {collection_ts: $cts})
OPTIONAL MATCH (d)-[:LOCATED_IN]->(s:Site)
OPTIONAL MATCH (d)-[:MEMBER_OF]->(g:RedundancyGroup)
WITH d, min(s.code) AS site, min(s.kind) AS site_kind, min(g.uid) AS group_uid,
     EXISTS { MATCH (d)-[:HAS_LINK]->(:WanLink) } AS wan
RETURN d.uid AS uid, coalesce(d.hostname, d.uid) AS label, d.role AS role, d.tier AS tier,
       d.vendor AS vendor, d.model AS model, coalesce(d.os_version, d.software_version) AS os_version,
       d.mgmt_ip AS mgmt_ip, d.platform AS platform, d.bound_device_uid AS bound_device_uid,
       coalesce(d.carried, false) AS carried,
       d.carried_reason AS carried_reason, d.last_seen_ts AS last_seen_ts,
       site, site_kind, group_uid, wan
"""

# A seek on the `obj_uid_cts` constraint on :Obj.
_ANCHOR = (
    "MATCH (d:Obj) USING INDEX d:Obj(uid, collection_ts)\n"
    "WHERE d.uid IN $uids AND d.collection_ts = $cts AND d:Device\n"
)


def _query(pattern: str) -> str:
    return _ANCHOR + f"OPTIONAL MATCH {pattern}\nRETURN d.uid AS device, collect(DISTINCT x.uid) AS xs"


def _gate(label: str, node: str) -> list[str]:
    return [p.replace("(g)", node) for p in GATE_BINDINGS[label]]


_PORT = "(x:Port)-[:ON]->(d)"
_REALIZED_IN_CONTEXT = (
    "EXISTS { MATCH (i:Interface)-[:REALIZED_BY]->(x) "
    "WHERE EXISTS { MATCH (i)-[:IN_VRF|IN_CONTEXT]->() } OR EXISTS { MATCH (:Zone)-[:CONTAINS]->(i) } }"
)
_NOT_INSTANCE_VRF = "NOT EXISTS { MATCH (x)-[:IN_CONTEXT]->(:FirewallInstance) }"
_RULEBASES = _gate("FwRulebase", "(g:FwRulebase)")

# The objects each count column counts, as the union of these paths from `d` to `x`.
CATEGORIES: dict[str, tuple[str, ...]] = {
    "n_ports": (_PORT,),
    "n_ports_connected": (f"{_PORT} WHERE EXISTS {{ MATCH (x)-[:CONNECTED_TO]-(:Port) }}",),
    "n_ports_up": (
        f"{_PORT} WHERE x.oper_status = 'up' OR x.oper = 'up' "
        "OR EXISTS { MATCH (i:Interface)-[:REALIZED_BY]->(x) WHERE i.oper_status = 'up' }",
    ),
    "n_interfaces": ("(x:Interface)-[:ON]->(d)",),
    "n_vrfs": ("(x:VrfInstance)-[:OWNED_BY]->(d)", "(d)<-[:ON]-(:Interface)-[:IN_VRF]->(x:VrfInstance)"),
    "n_vlans": (
        "(d)<-[:ON]-(:Port)-[:CARRIES|BOUND_TO]->(x:VlanInstance)",
        "(d)<-[:ON]-(:Interface)-[:CARRIES|BOUND_TO]->(x:VlanInstance)",
    ),
    "n_prefixes": ("(d)<-[:ON]-(:Interface)-[:HAS_IP]->(:IpAddress)-[:IN]->(x:Prefix)",),
    "n_rulebases": tuple(_gate("FwRulebase", "(x:FwRulebase)")),
    "n_rules": tuple(f"{p}, (g)-[:HAS_RULE]->(x:FwRule)" for p in _RULEBASES),
    "n_nat_rules": tuple(f"{p}, (g)-[:HAS_RULE]->(x:NatRule)" for p in _RULEBASES),
    "n_pbr": tuple(_gate("PbrPolicy", "(x:PbrPolicy)")),
    "n_sessions": ("(d)<-[:OWNED_BY]-(:VrfInstance)<-[:IN_VRF]-(:RoutingProcess)-[:HAS]->(x:BgpSession)",),
    "n_tunnels": (
        "(x:Tunnel)-[:ENDPOINT]->(d)",
        "(x:Tunnel)-[:ENDPOINT]->()-[:ON]->(d)",
        "(x:Tunnel)-[:ENDPOINT]->(:IpAddress)<-[:HAS_IP]-(:Interface)-[:ON]->(d)",
    ),
    "n_endpoints": ("(x:Endpoint)-[:ATTACHED]->(d)", "(x:Endpoint)-[:ATTACHED]->()-[:ON]->(d)"),
    "n_contexts": (
        f"(x:VrfInstance)-[:OWNED_BY]->(d) WHERE {_NOT_INSTANCE_VRF}",
        f"(d)<-[:ON]-(:Interface)-[:IN_VRF]->(x:VrfInstance) WHERE {_NOT_INSTANCE_VRF}",
        "(x:FirewallInstance)-[:RUNS_ON]->(d)",
        "(x:Zone)-[:OWNED_BY]->(d)",
    ),
    "n_ports_with_context": (f"{_PORT} WHERE {_REALIZED_IN_CONTEXT}",),
    "n_ports_with_port_edge": (f"{_PORT} WHERE EXISTS {{ MATCH (:Interface)-[:REALIZED_BY]->(x) }}",),
}
# The label of the objects each column counts, for the binding index.
CATEGORY_LABEL: dict[str, str] = {
    "n_interfaces": "Interface",
    "n_vrfs": "VrfInstance",
    "n_vlans": "VlanInstance",
    "n_prefixes": "Prefix",
    "n_rulebases": "FwRulebase",
    "n_rules": "FwRule",
    "n_nat_rules": "NatRule",
    "n_pbr": "PbrPolicy",
    "n_sessions": "BgpSession",
    "n_tunnels": "Tunnel",
    "n_endpoints": "Endpoint",
    "n_contexts": "Context",
}

PORTS = (
    _ANCHOR
    + """MATCH (x:Port)-[:ON]->(d)
OPTIONAL MATCH (x)-[:MEMBER_OF]->(l:Lag)
OPTIONAL MATCH (i:Interface)-[:REALIZED_BY]->(x)
OPTIONAL MATCH (i)-[:IN_VRF|IN_CONTEXT]->(c)
OPTIONAL MATCH (z:Zone)-[:CONTAINS]->(i)
WITH d, x, min(l.uid) AS lag_uid, min(i.uid) AS interface_uid, min(i.admin_up) AS if_admin_up,
     min(i.oper_status) AS if_oper, min(c.uid) AS context_uid, min(z.uid) AS zone_uid,
     EXISTS { MATCH (x)-[:CONNECTED_TO]-(:Port) } AS connected
RETURN d.uid AS device, x.uid AS uid, x.name AS name,
       coalesce(x.admin_state, x.admin) AS admin, coalesce(x.oper_status, x.oper) AS oper,
       x.speed_mbps AS speed_mbps, x.speed AS speed, lag_uid, interface_uid, if_admin_up, if_oper,
       coalesce(context_uid, zone_uid) AS context_uid, connected"""
)

CABLES = (
    _ANCHOR
    + """MATCH (d)<-[:ON]-(p1:Port)-[c:CONNECTED_TO]-(p2:Port)-[:ON]->(d2:Device)
RETURN d.uid AS a_dev, p1.uid AS a_port, d2.uid AS b_dev, p2.uid AS b_port, c.source AS source,
       coalesce(c.carried, false) AS carried,
       coalesce(p1.speed_mbps, p1.speed) AS a_speed, coalesce(p2.speed_mbps, p2.speed) AS b_speed"""
)


def _tunnel_ends(near: str, far: str) -> str:
    """The tunnels with their `near` end on `d` and their `far` end on another device."""
    return (
        _ANCHOR
        + f"""CALL (d) {{
  MATCH (t:Tunnel)-[:{near}]->(d) RETURN t, d AS a
  UNION
  MATCH (t:Tunnel)-[:{near}]->(a)-[:ON]->(d) RETURN t, a
  UNION
  MATCH (t:Tunnel)-[:{near}]->(a)<-[:HAS_IP]-(:Interface)-[:ON]->(d) RETURN t, a
}}
MATCH (t)-[:{far}]->(b)
CALL (b) {{
  WITH b AS o WHERE o:Device RETURN o
  UNION
  MATCH (b)-[:ON]->(o:Device) RETURN o
  UNION
  MATCH (b)<-[:HAS_IP]-(:Interface)-[:ON]->(o:Device) RETURN o
}}
RETURN d.uid AS device, o.uid AS other, t.uid AS tunnel, t.encap AS encap"""
    )


TUNNELS_LOCAL = _tunnel_ends("ENDPOINT", "TERMINATES_ON")
TUNNELS_FAR = _tunnel_ends("TERMINATES_ON", "ENDPOINT")

CONTEXTS = (
    _ANCHOR
    + f"""CALL (d) {{
  MATCH (x:VrfInstance)-[:OWNED_BY]->(d) WHERE {_NOT_INSTANCE_VRF}
  RETURN x
  UNION
  MATCH (d)<-[:ON]-(:Interface)-[:IN_VRF]->(x:VrfInstance) WHERE {_NOT_INSTANCE_VRF}
  RETURN x
  UNION
  MATCH (x:FirewallInstance)-[:RUNS_ON]->(d)
  RETURN x
  UNION
  MATCH (x:Zone)-[:OWNED_BY]->(d)
  RETURN x
}}
RETURN d.uid AS device, x.uid AS uid, labels(x) AS labels, x.name AS name, x.kind AS kind,
       x.rd AS rd, x.is_default AS is_default"""
)


# One row per device and bridge domain with client endpoints attached on the ports, the interfaces or
# the device itself (an access point). The prefix is the most common home of the clients'
# addresses. An endpoint in no bridge domain counts under the null bridge domain.
SEGMENTS = (
    _ANCHOR
    + """CALL (d) {
  MATCH (ep:Endpoint)-[:ATTACHED]->(d) RETURN ep
  UNION
  MATCH (ep:Endpoint)-[:ATTACHED]->()-[:ON]->(d) RETURN ep
}
OPTIONAL MATCH (ep)-[:IN]->(bd:BridgeDomain)
OPTIONAL MATCH (ep)-[:HAS_IP]->(:IpAddress)-[:IN]->(pfx:Prefix)
WITH d, bd, ep, min(pfx.cidr) AS cidr
WITH d, bd, count(DISTINCT ep) AS clients, collect(cidr) AS cidrs
UNWIND (CASE WHEN size(cidrs) = 0 THEN [null] ELSE cidrs END) AS cidr
WITH d, bd, clients, cidr, count(cidr) AS votes
ORDER BY votes DESC, cidr
WITH d, bd, clients, collect(cidr)[0] AS prefix
RETURN d.uid AS device, bd.uid AS bridge_domain_uid, bd.vid AS vid, bd.name AS name, prefix,
       clients AS client_count"""
)

# The clients of one segment are the endpoints attached on the device in the bridge domain, with their port.
SEGMENT_CLIENTS = """
MATCH (d:Device:Obj {uid: $device, collection_ts: $cts})
CALL (d) {
  MATCH (ep:Endpoint)-[:ATTACHED]->(d) RETURN ep, d AS x
  UNION
  MATCH (ep:Endpoint)-[:ATTACHED]->(x)-[:ON]->(d) RETURN ep, x
}
OPTIONAL MATCH (ep)-[:IN]->(bd:BridgeDomain)
WITH ep, x, bd WHERE ($bd IS NULL AND bd IS NULL) OR bd.uid = $bd
OPTIONAL MATCH (ep)-[:HAS_IP]->(ip:IpAddress)
WITH ep, x, collect(DISTINCT ip.ip) AS ips
RETURN ep.uid AS uid, coalesce(ep.name, ep.hostname) AS name, ep.mac AS mac, ips,
       CASE WHEN x:Port OR x:Interface THEN x.name ELSE null END AS port, ep.last_seen_ts AS last_seen_ts
ORDER BY name, mac
"""


# The Fabric ports of the run. A row holds a Fabric port with its properties, its `LOCATED_IN` site,
# and the first account port that realizes it (`REALIZED_BY`) with the device and the site of that port.
FABRIC_PORTS = """
MATCH (f:FabricPort:Obj {collection_ts: $cts})
OPTIONAL MATCH (f)-[:LOCATED_IN]->(s:Site)
WITH f, min(s.code) AS located
OPTIONAL MATCH (f)-[r:REALIZED_BY]->(p:Port)-[:ON]->(d:Device)
OPTIONAL MATCH (d)-[:LOCATED_IN]->(ds:Site)
WITH f, located, r, p, d, min(ds.code) AS device_site
ORDER BY p.uid
WITH f, located, collect({
       port: p.uid, device: d.uid, site: device_site,
       by: CASE WHEN r IS NULL THEN null
                WHEN r.derived THEN coalesce(r.evidence, 'derived') ELSE 'operator' END
     })[0] AS bound
RETURN f.uid AS uid, f.name AS name, f.state AS state, f.metro AS metro, f.ibx AS ibx,
       f.speed_mbps AS speed_mbps, f.redundancy AS redundancy, f.lag_name AS lag_name,
       f.cross_connect_ids AS cable_ids, f.bound_port_uid AS binding, f.binding_issue AS binding_issue,
       f.binding_ports AS binding_ports, located,
       bound.port AS port, bound.device AS device, bound.site AS device_site, bound.by AS bound_by
"""


def _circuit_end(side: str, rel: str) -> str:
    """The `side` end of a circuit, as the Fabric port or the Network Edge interface, with the
    account's device and port behind it."""
    return f"""CALL (c) {{
  OPTIONAL MATCH (c)-[r:{rel}]->(x)
  OPTIONAL MATCH (x)-[:REALIZED_BY]->(p:Port)-[:ON]->(d:Device)
  OPTIONAL MATCH (x)-[:ON]->(nd:Device)
  RETURN x.uid AS {side}_end, labels(x) AS {side}_labels, coalesce(d.uid, nd.uid) AS {side}_device,
         p.uid AS {side}_port, r.vlan_tag AS {side}_vlan
  LIMIT 1
}}"""


# The virtual circuits of the run with both ends.
CIRCUITS = f"""
MATCH (c:VirtualCircuit:Obj {{collection_ts: $cts}})
{_circuit_end("a", "A_END")}
{_circuit_end("z", "Z_END")}
RETURN c.uid AS uid, c.name AS name, c.type AS type, c.state AS state, c.bandwidth_mbps AS bandwidth_mbps,
       c.provider AS provider, a_end, a_labels, a_device, a_port, a_vlan,
       z_end, z_labels, z_device, z_port, z_vlan
"""


class Session(Protocol):
    def run(self, query: str, **params: Any) -> Any: ...


def _rows(session: Session, query: str, **params: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = session.run(query, **params).data()
    return rows


def _batches(uids: Sequence[str]) -> Iterator[list[str]]:
    for i in range(0, len(uids), BATCH):
        yield list(uids[i : i + BATCH])


@dataclass
class DeviceFacts:
    """What the tiers hold for one set of devices at one run."""

    devices: dict[str, dict[str, Any]] = field(default_factory=dict)
    members: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    ports: list[dict[str, Any]] = field(default_factory=list)
    cables: list[dict[str, Any]] = field(default_factory=list)
    tunnels: list[dict[str, Any]] = field(default_factory=list)
    contexts: list[dict[str, Any]] = field(default_factory=list)
    segments: list[dict[str, Any]] = field(default_factory=list)

    def counts(self, device: str) -> dict[str, int]:
        found = self.members.get(device, {})
        return {name: len(found.get(name, ())) for name in COUNTS}


def device_rows(session: Session, cts: int) -> dict[str, dict[str, Any]]:
    return {row["uid"]: row for row in _rows(session, DEVICES, cts=cts)}


def fabric(session: Session, cts: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The Fabric ports and the virtual circuits of the run, read in full."""
    return _rows(session, FABRIC_PORTS, cts=cts), _rows(session, CIRCUITS, cts=cts)


def read(session: Session, cts: int, uids: Iterable[str]) -> DeviceFacts:
    """The facts of the devices `uids` that exist at `cts`."""
    wanted = sorted(set(uids))
    facts = DeviceFacts()
    for batch in _batches(wanted):
        for name, paths in CATEGORIES.items():
            for path in paths:
                for row in _rows(session, _query(path), cts=cts, uids=batch):
                    facts.members.setdefault(row["device"], {}).setdefault(name, set()).update(row["xs"])
        facts.ports.extend(_rows(session, PORTS, cts=cts, uids=batch))
        facts.cables.extend(_rows(session, CABLES, cts=cts, uids=batch))
        facts.tunnels.extend(_rows(session, TUNNELS_LOCAL, cts=cts, uids=batch))
        facts.tunnels.extend(_rows(session, TUNNELS_FAR, cts=cts, uids=batch))
        facts.contexts.extend(_rows(session, CONTEXTS, cts=cts, uids=batch))
        facts.segments.extend(_rows(session, SEGMENTS, cts=cts, uids=batch))
    return facts


def queries() -> list[str]:
    """Every per-device query of this module, for the plan assertion."""
    return [
        *(_query(p) for paths in CATEGORIES.values() for p in paths),
        PORTS,
        CABLES,
        TUNNELS_LOCAL,
        TUNNELS_FAR,
        CONTEXTS,
        SEGMENTS,
    ]


_SPEED = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)", re.IGNORECASE)
_UNIT_MBPS = {"": 1, "k": 0.001, "m": 1, "g": 1000, "t": 1_000_000}


def speed_mbps(value: Any) -> int | None:
    """Megabits per second from a number or a string such as `10g`."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return int(value)
    match = _SPEED.match(str(value))
    if match is None:
        return None
    return int(float(match.group(1)) * _UNIT_MBPS[match.group(2).lower()])


_SHORT = (
    ("hundredgigabitethernet", "Hu"),
    ("fortygigabitethernet", "Fo"),
    ("twentyfivegige", "Twe"),
    ("tengigabitethernet", "Te"),
    ("gigabitethernet", "Gi"),
    ("fastethernet", "Fa"),
    ("port-channel", "Po"),
    ("ethernet", "Eth"),
)


def name_short(name: str | None) -> str | None:
    if name is None:
        return None
    lower = name.lower()
    for long, short in _SHORT:
        if lower.startswith(long):
            return short + name[len(long) :]
    return name


def admin_status(row: Mapping[str, Any]) -> str | None:
    if row.get("admin") is not None:
        return str(row["admin"])
    if row.get("if_admin_up") is not None:
        return "up" if row["if_admin_up"] else "down"
    return None


def oper_status(row: Mapping[str, Any]) -> str | None:
    value = row.get("oper") if row.get("oper") is not None else row.get("if_oper")
    return None if value is None else str(value)
