"""A Business Application with its resolved inventory, as a node-link graph.

The catalog is in Postgres, and the module writes nothing to the graph. The
graph is joined at read time. It holds synthetic nodes for the application,
its services, groups and connections (ids `app:`, `service:`, `group:`,
`conn:`, and `member:` for a member with no inventory object). It also holds
the inventory objects that the resolution bound at the pinned run, with their
device anchors.

The shape is the Explore graph payload (`app/tables.py` `_GraphCollector`).
The GraphView of Explore draws it as it draws a query result.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from hst import path as pathmod
from hst.app.tables import MAX_GRAPH_NODES, MAX_GRAPH_RELS, _ordered_labels

# The most neighbours of one kind a member contributes.
FANOUT = 25

_PROPS = "{.uid, .name, .hostname, .ip, .cidr, .prefix, .fqdn, .role, .vendor, .site}"
_SERVICE_PROPS = "{.uid, .name, .vip, .port, .proto, .kind}"
_LIVE = "{r}.collection_ts = $snap AND {r}._retired_at IS NULL"
_AT_RUN = "{n}.collection_ts = $snap AND NOT {n}:Retired"

# The query returns one row per resolved inventory uid at the run. A row holds
# the object, its outgoing and incoming neighbours and the devices that hold
# it. `anchors` holds the device of the interface that holds the address, or
# that holds an address that a name resolves to. `services` holds the device
# that a virtual service is ON, or the member devices of the redundancy group
# that it is ON. The virtual service is the object or has the object as its VIP.
INVENTORY_QUERY = f"""
UNWIND $uids AS wanted
MATCH (n:Obj {{uid: wanted, collection_ts: $snap}}) WHERE NOT n:Retired
RETURN n.uid AS uid, labels(n) AS labels, n {_PROPS} AS props,
 [(n)-[r:HAS_IP|RESOLVES_TO|IN_VRF|IN|ON]->(m:Obj)
   WHERE {_LIVE.format(r="r")} AND m.collection_ts = $snap AND NOT m:Retired
   | {{type: type(r), uid: m.uid, labels: labels(m), props: m {_PROPS}}}][0..$fanout] AS outgoing,
 [(m:Obj)-[r:HAS_IP|VIP|RESOLVES_TO]->(n)
   WHERE {_LIVE.format(r="r")} AND m.collection_ts = $snap AND NOT m:Retired
   | {{type: type(r), uid: m.uid, labels: labels(m), props: m {_PROPS}}}][0..$fanout] AS incoming,
 [(n)-[x:RESOLVES_TO*0..1]->(a:Obj)<-[h:HAS_IP]-(i:Interface)-[o:ON]->(d:Device)
   WHERE all(e IN x WHERE {_LIVE.format(r="e")}) AND {_LIVE.format(r="h")} AND {_LIVE.format(r="o")}
     AND a.collection_ts = $snap AND i.collection_ts = $snap AND d.collection_ts = $snap
     AND NOT a:Retired AND NOT i:Retired AND NOT d:Retired
   | {{address: a.uid, interface: i.uid, interface_props: i {_PROPS}, uid: d.uid, labels: labels(d),
       props: d {_PROPS}}}][0..$fanout] AS anchors,
 ([(n)<-[x:VIP*0..1]-(vs:VirtualService)-[o:ON]->(d:Device)
   WHERE all(e IN x WHERE {_LIVE.format(r="e")}) AND {_LIVE.format(r="o")}
     AND {_AT_RUN.format(n="vs")} AND {_AT_RUN.format(n="d")}
   | {{service: vs.uid, service_props: vs {_SERVICE_PROPS}, group: null, group_props: null,
       uid: d.uid, labels: labels(d), props: d {_PROPS}}}]
  + [(n)<-[x:VIP*0..1]-(vs:VirtualService)-[o:ON]->(g:RedundancyGroup)<-[m:MEMBER_OF]-(d:Device)
   WHERE all(e IN x WHERE {_LIVE.format(r="e")}) AND {_LIVE.format(r="o")} AND {_LIVE.format(r="m")}
     AND {_AT_RUN.format(n="vs")} AND {_AT_RUN.format(n="g")} AND {_AT_RUN.format(n="d")}
   | {{service: vs.uid, service_props: vs {_SERVICE_PROPS}, group: g.uid, group_props: g {{.uid, .name}},
       uid: d.uid, labels: labels(d), props: d {_PROPS}}}])[0..$fanout] AS services
"""


def inventory_uids(resolution: Mapping[str, Any]) -> list[str]:
    """The inventory uids a resolution bound, once each, in a fixed order."""
    return sorted(
        {
            str(member["inventory_uid"])
            for members in (resolution.get("groups") or {}).values()
            for member in members.values()
            if member.get("inventory_uid")
        }
    )


def read_inventory(session: Any, snapshot_cts: int, uids: list[str]) -> list[dict]:
    """The `INVENTORY_QUERY` rows of `uids` at the run `snapshot_cts`."""
    if not uids:
        return []
    return list(pathmod._read(session, INVENTORY_QUERY, uids=uids, snap=snapshot_cts, fanout=FANOUT))


def device_anchors(rows: Iterable[Mapping[str, Any]]) -> dict[str, list[str]]:
    """Map each inventory uid to the uids of the devices that hold it.

    A device is its own anchor. An interface or a port has the device that it
    is ON. An address or a name has the device of the interface that holds the
    address. A virtual service or its VIP has the device that the service is
    ON, or the member devices of the redundancy group that the service is ON."""
    out: dict[str, list[str]] = {}
    for row in rows:
        devices = set()
        if "Device" in (row.get("labels") or []):
            devices.add(str(row["uid"]))
        for edge in row.get("outgoing") or []:
            if edge.get("type") == "ON" and "Device" in (edge.get("labels") or []):
                devices.add(str(edge["uid"]))
        for anchor in [*(row.get("anchors") or []), *(row.get("services") or [])]:
            devices.add(str(anchor["uid"]))
        out[str(row["uid"])] = sorted(devices)
    return out


class _Graph:
    """Nodes and relationships by id, capped as an Explore result is."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.rels: dict[str, dict] = {}
        self.truncated = False

    def node(self, identifier: str, labels: list[str], properties: Mapping[str, Any]) -> bool:
        known = self.nodes.get(identifier)
        if known is not None:
            # One object can return through 2 reads with different projections,
            # for example a virtual service as the neighbour of its VIP and as a
            # service anchor. The node keeps the union of the properties.
            for key, value in properties.items():
                if value is not None:
                    known["properties"].setdefault(key, value)
            return True
        if len(self.nodes) >= MAX_GRAPH_NODES:
            self.truncated = True
            return False
        clean = {key: value for key, value in properties.items() if value is not None}
        self.nodes[identifier] = {"id": identifier, "labels": labels, "properties": clean}
        return True

    def rel(self, kind: str, start: str, end: str, properties: Mapping[str, Any] | None = None) -> None:
        identifier = f"{start}|{kind}|{end}"
        if identifier in self.rels:
            return
        if start not in self.nodes or end not in self.nodes or len(self.rels) >= MAX_GRAPH_RELS:
            self.truncated = True
            return
        self.rels[identifier] = {
            "id": identifier,
            "type": kind,
            "start": start,
            "end": end,
            "properties": dict(properties or {}),
        }

    def inventory(self, uid: str, labels: list[str], props: Mapping[str, Any] | None) -> bool:
        return self.node(uid, _ordered_labels(labels), {**(props or {}), "uid": uid})


def application_graph(
    definition: Mapping[str, Any],
    *,
    revision: int,
    resolution: Mapping[str, Any],
    rows: Iterable[Mapping[str, Any]],
) -> dict:
    """The graph payload of `definition` at the run its `resolution` names,
    with the inventory `rows` of `read_inventory`."""
    graph = _Graph()
    app = f"app:{definition['id']}"
    graph.node(
        app,
        ["BusinessApplication"],
        {"id": definition["id"], "name": definition.get("name"), "revision": revision},
    )
    readiness = {item["id"]: item.get("readiness") for item in resolution.get("connections") or []}
    associated: set[str] = set()
    for service in definition.get("services") or []:
        identifier = f"service:{service['id']}"
        graph.node(identifier, ["ApplicationService"], {"id": service["id"], "name": service.get("name")})
        graph.rel("HAS_SERVICE", app, identifier)
    for group in definition.get("groups") or []:
        identifier = f"group:{group['id']}"
        graph.node(identifier, ["ComponentGroup"], {"id": group["id"], "name": group.get("name")})
        graph.rel("HAS_GROUP", app, identifier)
    for connection in definition.get("connections") or []:
        identifier = f"conn:{connection['id']}"
        ports = connection.get("destination_ports")
        graph.node(
            identifier,
            ["ApplicationConnection"],
            {
                "id": connection["id"],
                "name": connection.get("name"),
                "protocol": connection.get("protocol"),
                "destination_ports": ", ".join(str(port) for port in ports) if ports else None,
                "success": connection.get("success"),
                "readiness": readiness.get(connection["id"], "not resolved"),
            },
        )
        graph.rel("FROM", identifier, f"group:{connection['source']}")
        graph.rel("TO", identifier, f"group:{connection['destination']}")
    for service in definition.get("services") or []:
        for connection_id in service.get("connection_ids") or []:
            graph.rel("ASSOCIATES", f"service:{service['id']}", f"conn:{connection_id}")
            associated.add(connection_id)
    for connection in definition.get("connections") or []:
        if connection["id"] not in associated:
            graph.rel("HAS_CONNECTION", app, f"conn:{connection['id']}")

    by_uid = {str(row["uid"]): row for row in rows}
    resolved = resolution.get("groups") or {}
    for group in definition.get("groups") or []:
        for member in group.get("members") or []:
            bound = (resolved.get(group["id"]) or {}).get(member["id"]) or {}
            uid = bound.get("inventory_uid")
            row = by_uid.get(str(uid)) if uid else None
            if row is not None and graph.inventory(str(uid), list(row.get("labels") or []), row.get("props")):
                graph.rel("MEMBER", f"group:{group['id']}", str(uid), {"member": member["id"]})
                continue
            identifier = f"member:{group['id']}/{member['id']}"
            placeholder = member.get("placeholder") or {}
            state = (
                "not resolved at this run"
                if group["id"] not in resolved
                else "resolved"
                if bound.get("bindings")
                else "unresolved"
            )
            graph.node(
                identifier,
                ["ApplicationMember"],
                {
                    "id": member["id"],
                    "name": member.get("name"),
                    "address": member.get("address"),
                    "inventory_uid": (member.get("inventory") or {}).get("uid"),
                    "placeholder": placeholder.get("text"),
                    "state": state,
                },
            )
            graph.rel("MEMBER", f"group:{group['id']}", identifier, {"member": member["id"]})

    for uid, row in by_uid.items():
        if uid not in graph.nodes:
            continue
        for edge in row.get("outgoing") or []:
            if graph.inventory(str(edge["uid"]), list(edge.get("labels") or []), edge.get("props")):
                graph.rel(str(edge["type"]), uid, str(edge["uid"]))
        for edge in row.get("incoming") or []:
            if graph.inventory(str(edge["uid"]), list(edge.get("labels") or []), edge.get("props")):
                graph.rel(str(edge["type"]), str(edge["uid"]), uid)
        for anchor in row.get("anchors") or []:
            interface, device, address = str(anchor["interface"]), str(anchor["uid"]), str(anchor["address"])
            if not graph.inventory(interface, ["Interface"], anchor.get("interface_props")):
                continue
            if graph.inventory(device, list(anchor.get("labels") or []), anchor.get("props")):
                graph.rel("ON", interface, device)
            if address == uid or graph.inventory(address, ["IpAddress"], {}):
                graph.rel("HAS_IP", interface, address)
            if address != uid:
                graph.rel("RESOLVES_TO", uid, address)
        for anchor in row.get("services") or []:
            service, device, group = str(anchor["service"]), str(anchor["uid"]), anchor.get("group")
            if not graph.inventory(service, ["VirtualService"], anchor.get("service_props")):
                continue
            if service != uid:
                graph.rel("VIP", service, uid)
            if not graph.inventory(device, list(anchor.get("labels") or []), anchor.get("props")):
                continue
            if group is None:
                graph.rel("ON", service, device)
            elif graph.inventory(str(group), ["RedundancyGroup"], anchor.get("group_props")):
                graph.rel("ON", service, str(group))
                graph.rel("MEMBER_OF", device, str(group))
    return {
        "nodes": list(graph.nodes.values()),
        "relationships": list(graph.rels.values()),
        "truncated": graph.truncated,
    }
