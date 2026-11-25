"""The inventory graph builder (hst/applications/inventory_graph.py) on rows
shaped as INVENTORY_QUERY returns them; the query itself runs against Neo4j in
tests/app/test_application_inventory_db.py."""

from __future__ import annotations

from hst.applications import inventory_graph

DEFINITION = {
    "id": "shop",
    "name": "Shop",
    "groups": [
        {
            "id": "servers",
            "name": "Servers",
            "members": [{"id": "vip", "inventory": {"kind": "ip", "uid": "ip:vip"}}],
        }
    ],
    "connections": [],
    "services": [],
}
RESOLUTION = {
    "groups": {"servers": {"vip": {"bindings": [{"address": "10.0.0.100"}], "inventory_uid": "ip:vip"}}}
}


def service(device, group=None):
    return {
        "service": "vs:shop",
        "service_props": {"vip": "10.0.0.100"},
        "group": group,
        "group_props": {"name": group} if group else None,
        "uid": device,
        "labels": ["Obj", "Device"],
        "props": {"hostname": device},
    }


ROW = {
    "uid": "ip:vip",
    "labels": ["Obj", "IpAddress"],
    "props": {"ip": "10.0.0.100"},
    "outgoing": [],
    "incoming": [],
    "anchors": [],
    "services": [service("dev:lb1", "rg:lb"), service("dev:lb2", "rg:lb"), service("dev:lb3")],
}


def test_a_vip_is_anchored_to_the_devices_its_virtual_service_is_on():
    assert inventory_graph.device_anchors([ROW]) == {"ip:vip": ["dev:lb1", "dev:lb2", "dev:lb3"]}


def test_the_graph_draws_the_virtual_service_its_group_and_its_devices():
    graph = inventory_graph.application_graph(DEFINITION, revision=1, resolution=RESOLUTION, rows=[ROW])
    nodes = {node["id"]: node["labels"][0] for node in graph["nodes"]}
    assert nodes["vs:shop"] == "VirtualService"
    assert nodes["rg:lb"] == "RedundancyGroup"
    edges = {(rel["start"], rel["type"], rel["end"]) for rel in graph["relationships"]}
    assert {
        ("group:servers", "MEMBER", "ip:vip"),
        ("vs:shop", "VIP", "ip:vip"),
        ("vs:shop", "ON", "rg:lb"),
        ("dev:lb1", "MEMBER_OF", "rg:lb"),
        ("dev:lb2", "MEMBER_OF", "rg:lb"),
        ("vs:shop", "ON", "dev:lb3"),
    } <= edges
