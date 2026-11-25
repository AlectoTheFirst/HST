"""Equinix collector: the Fabric port fields the reasoner binds with, the
sorted connection search, and the opt-in Network Edge read (devices,
interfaces, credential removal and the circuit ends on a virtual device).

Hand payloads in the shape of the Fabric v4 and Network Edge v1 answers; every
name, uuid and number here is made up."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from hst.collectors import equinix
from hst.collectors.auth import OAuthClientCredentials
from hst.collectors.equinix import EquinixCollector, EquinixConfig, normalize_equinix
from hst.core import uid

PORT_PRI = "aaaaaaaa-0000-4000-8000-000000000001"
PORT_SEC = "aaaaaaaa-0000-4000-8000-000000000002"
EDGE_FW = "bbbbbbbb-0000-4000-8000-000000000001"
EDGE_IF_ETH0 = "cccccccc-0000-4000-8000-000000000000"
EDGE_IF_ETH1 = "cccccccc-0000-4000-8000-000000000001"
CONN_EDGE = "dddddddd-0000-4000-8000-000000000001"
CONN_FOREIGN = "dddddddd-0000-4000-8000-000000000002"
EDGE_DEV = uid.equinix("device", EDGE_FW)
# the device another source collects for the same box
BOUND_DEV = "vco:ent-1:edge:edge-1"


def _port(uuid: str, name: str, *, priority: str, cable: str, lag: dict[str, Any]) -> dict[str, Any]:
    return {
        "uuid": uuid,
        "name": name,
        "state": "ACTIVE",
        "bandwidth": 10000,
        "location": {"ibx": "XX1", "metroCode": "XX"},
        "encapsulation": {"type": "DOT1Q"},
        "redundancy": {"priority": priority},
        "lag": lag,
        "physicalPorts": [{"tether": {"crossConnectId": cable}}],
    }


PORTS = [
    _port(PORT_PRI, "ACME-XX1-EXT-PRI-01", priority="PRIMARY", cable="21000001", lag={"enabled": False}),
    _port(
        PORT_SEC,
        "ACME-XX1-EXT-SEC-01",
        priority="SECONDARY",
        cable="21000002-A",
        lag={"enabled": True, "id": "1", "name": "ae9"},
    ),
]

EDGE_DEVICE = {
    "uuid": EDGE_FW,
    "name": "XX-EDGE-FW-01",
    "hostName": "xx-edge-fw-01",
    "deviceTypeCode": "CGUARD",
    "deviceTypeVendor": "Check Point",
    "deviceTypeCategory": "FIREWALL",
    "status": "PROVISIONED",
    "version": "R81.20",
    "ibx": "XX1",
    "metroCode": "XX",
    "redundancyType": "PRIMARY",
    "sshIpAddress": "192.0.2.10",
    "vendorConfig": {"adminPassword": "not-a-real-password"},
    "interfaces": [
        {
            "id": 1,
            "name": "eth0",
            "type": "DATA",
            "status": "ASSIGNED",
            "assignedType": "XX_EDGE_FW_PRI",
            "uuid": EDGE_IF_ETH0,
            "macAddress": "00:00:5e:00:53:01",
        },
        {
            "id": 2,
            "name": "eth1",
            "type": "DATA",
            "status": "AVAILABLE",
            "assignedType": "",
            "uuid": EDGE_IF_ETH1,
        },
        {"id": 8, "name": "eth7", "type": "SSH", "status": None, "assignedType": "Equinix Managed"},
    ],
}


EDGE_RTR = "bbbbbbbb-0000-4000-8000-000000000002"
EDGE_HUB = "bbbbbbbb-0000-4000-8000-000000000003"


def _edge_device(uuid: str, name: str, interfaces: list[tuple[int, str]]) -> dict[str, Any]:
    return {
        "uuid": uuid,
        "name": name,
        "deviceTypeCode": "C8000V",
        "deviceTypeVendor": "Cisco",
        "deviceTypeCategory": "ROUTER",
        "status": "PROVISIONED",
        "ibx": "XX1",
        "interfaces": [
            {"id": n, "name": ifname, "type": "DATA", "uuid": f"{uuid[:-4]}if{n:02d}"}
            for n, ifname in interfaces
        ],
    }


EDGE_ROUTER_DEVICE = _edge_device(
    EDGE_RTR, "XX-EDGE-RTR-01", [(6, "GigabitEthernet6"), (7, "GigabitEthernet7")]
)
EDGE_HUB_DEVICE = _edge_device(EDGE_HUB, "XX-EDGE-HUB-01", [(2, "GigabitEthernet0/2")])


def _member(device_uuid: str, interface_id: int, name: str) -> dict[str, Any]:
    return {
        "deviceUuid": device_uuid,
        "interfaceId": interface_id,
        "interfaceName": name,
        "status": "PROVISIONED",
    }


LINK_PAIR = {
    "uuid": "cccccccc-1111-4000-8000-000000000001",
    "groupName": "XX-HOSTING",
    "status": "PROVISIONED",
    "redundancyType": "PRIMARY",
    "metroLinks": [],
    "linkDevices": [_member(EDGE_HUB, 2, "GigabitEthernet0/2"), _member(EDGE_RTR, 6, "GigabitEthernet6")],
}

# three members on the account's devices and one on another device
LINK_GROUP = {
    "uuid": "cccccccc-1111-4000-8000-000000000002",
    "groupName": "XX-INTERNAL",
    "status": "PROVISIONED",
    "metroLinks": [
        {"metroCode": "XX", "throughput": "200", "throughputUnit": "Mbps"},
        {"metroCode": "YY", "throughput": "500", "throughputUnit": "Mbps"},
    ],
    "linkDevices": [
        _member(EDGE_RTR, 7, "GigabitEthernet7"),
        _member(EDGE_FW, 2, "eth1"),
        _member(EDGE_HUB, 2, "GigabitEthernet0/2"),
        _member("not-in-the-device-list", 1, "eth0"),
    ],
}


def _edge_end(device_uuid: str, device_name: str, interface_uuid: str) -> dict[str, Any]:
    return {
        "accessPoint": {
            "type": "VD",
            "interface": {"uuid": interface_uuid, "id": 1, "type": "CLOUD"},
            "virtualDevice": {"uuid": device_uuid, "name": device_name, "type": "EDGE"},
        }
    }


def _port_end(port_uuid: str, tag: int) -> dict[str, Any]:
    return {
        "accessPoint": {
            "type": "COLO",
            "port": {"uuid": port_uuid},
            "linkProtocol": {"type": "DOT1Q", "vlanTag": tag},
        }
    }


CONNECTION_EDGE = {
    "uuid": CONN_EDGE,
    "name": "XX_EDGE_FW_PRI",
    "type": "EVPL_VC",
    "state": "ACTIVE",
    "aSide": _edge_end(EDGE_FW, "XX-EDGE-FW-01", EDGE_IF_ETH0),
    "zSide": _port_end(PORT_PRI, 830),
}

# a circuit from another party's virtual device to a port of the account
CONNECTION_FOREIGN = {
    "uuid": CONN_FOREIGN,
    "name": "OTHER_FW_NODE0",
    "type": "EVPL_VC",
    "state": "ACTIVE",
    "aSide": _edge_end("eeeeeeee-0000-4000-8000-000000000009", "OTHER-FW-NODE0", "not-in-the-list"),
    "zSide": _port_end(PORT_SEC, 2492),
}


def _raw(**extra: Any) -> dict[str, Any]:
    return {
        "api_profile": equinix.API_PROFILE,
        "fetched_at_ms": 1,
        "port_pages": [{"data": PORTS}],
        "connection_pages": [{"data": [CONNECTION_EDGE, CONNECTION_FOREIGN]}],
        **extra,
    }


def _norm(raw: dict[str, Any]):
    return normalize_equinix(raw, scope="equinix:test", ibx_sites={"XX1": "xx1"}, port_bindings={})


def _nodes(batch, label: str) -> dict[str, Any]:
    return {n.uid: n for n in batch.nodes if n.label == label}


# --- Fabric port fields --------------------------------------------------------------------


def test_a_fabric_port_carries_its_cable_ids_redundancy_and_lag():
    ports = _nodes(_norm(_raw()), "FabricPort")
    pri = ports[uid.equinix("port", PORT_PRI)].props
    sec = ports[uid.equinix("port", PORT_SEC)].props
    assert pri["cross_connect_ids"] == ["21000001"]
    assert pri["redundancy"] == "primary"
    assert "lag_name" not in pri
    # the `-A` suffix is dropped, so the id compares with a port description
    assert sec["cross_connect_ids"] == ["21000002"]
    assert sec["redundancy"] == "secondary"
    assert sec["lag_name"] == "ae9"


def test_a_virtual_device_end_is_named_on_the_circuit_even_without_network_edge():
    circuits = _nodes(_norm(_raw()), "VirtualCircuit")
    foreign = circuits[uid.equinix("connection", CONN_FOREIGN)].props
    assert foreign["a_virtual_device"] == "OTHER-FW-NODE0"
    assert foreign["a_side_kind"] == "vd"


# --- Network Edge normalization ------------------------------------------------------------


def test_a_network_edge_device_is_a_virtual_device_with_its_interfaces():
    batch = _norm(_raw(edge_device_pages=[{"data": [EDGE_DEVICE]}]))
    devices = _nodes(batch, "Device")
    # its own uid, outside the identity registry: it takes no hostname uid
    assert list(devices) == [EDGE_DEV]
    props = devices[EDGE_DEV].props
    assert props["platform"] == "network-edge"
    assert props["virtual"] is True
    assert props["role"] == "firewall"
    assert props["vendor"] == "Check Point"
    assert props["model"] == "CGUARD"
    assert props["edge_device_uuid"] == EDGE_FW
    assert props["edge_management_ip"] == "192.0.2.10"
    assert props["identities"] == ["XX-EDGE-FW-01", "xx-edge-fw-01"]

    interfaces = _nodes(batch, "Interface")
    eth0 = interfaces[uid.interface(EDGE_DEV, "eth0")].props
    assert eth0["edge_interface_uuid"] == EDGE_IF_ETH0
    assert eth0["assigned"] == "XX_EDGE_FW_PRI"
    assert eth0["mac"] is not None
    assert len(interfaces) == 3

    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert ("LOCATED_IN", EDGE_DEV, uid.site("xx1")) in rels
    assert ("PROVIDED_BY", EDGE_DEV, uid.provider("equinix")) in rels


def test_a_circuit_end_on_a_network_edge_interface_binds_to_that_interface():
    batch = _norm(_raw(edge_device_pages=[{"data": [EDGE_DEVICE]}]))
    ends = [
        (r.rel_type, r.start_uid, r.end_label, r.end_uid)
        for r in batch.rels
        if r.rel_type in ("A_END", "Z_END")
    ]
    edge_vc = uid.equinix("connection", CONN_EDGE)
    assert ("A_END", edge_vc, "Interface", uid.interface(EDGE_DEV, "eth0")) in ends
    assert ("Z_END", edge_vc, "FabricPort", uid.equinix("port", PORT_PRI)) in ends
    # the other party's device is not in the device list: its end stays unbound
    foreign_vc = uid.equinix("connection", CONN_FOREIGN)
    assert [e[0] for e in ends if e[1] == foreign_vc] == ["Z_END"]


def _bound(bindings: dict[str, str]):
    return normalize_equinix(
        _raw(edge_device_pages=[{"data": [EDGE_DEVICE]}]),
        scope="equinix:test",
        ibx_sites={"XX1": "xx1"},
        port_bindings={},
        edge_device_bindings=bindings,
    )


def test_a_bound_device_records_the_binding_and_writes_no_other_source_node():
    batch = _bound({EDGE_FW: BOUND_DEV})
    devices = _nodes(batch, "Device")
    # the batch never writes the device another source owns
    assert list(devices) == [EDGE_DEV]
    assert devices[EDGE_DEV].props["bound_device_uid"] == BOUND_DEV
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    # the site belongs to the source that owns the device
    assert not [r for r in rels if r[0] == "LOCATED_IN" and r[1] == EDGE_DEV]
    assert ("PROVIDED_BY", EDGE_DEV, uid.provider("equinix")) in rels
    assert ("A_END", uid.equinix("connection", CONN_EDGE), uid.interface(EDGE_DEV, "eth0")) in rels


def _bound_uid(bindings: dict[str, str]) -> str | None:
    return _nodes(_bound(bindings), "Device")[EDGE_DEV].props.get("bound_device_uid")


def test_a_binding_names_the_device_by_its_uuid_or_its_name_in_any_case():
    assert _bound_uid({EDGE_FW: BOUND_DEV}) == BOUND_DEV
    assert _bound_uid({"xx-edge-fw-01": BOUND_DEV}) == BOUND_DEV
    assert _bound_uid({"XX-EDGE-FW-01": BOUND_DEV}) == BOUND_DEV
    assert _bound_uid({"another-device": BOUND_DEV}) is None


def test_the_binding_config_is_parsed_and_checked():
    config = _config(edge_device_bindings=f"# hub\n{EDGE_FW}, {BOUND_DEV}\n")
    assert config.edge_device_binding_map == {EDGE_FW: BOUND_DEV}
    with pytest.raises(ValidationError, match="edge_device_bindings line 1"):
        _config(edge_device_bindings="no comma here")


def test_each_network_edge_interface_realizes_a_port_of_its_own():
    batch = _norm(_raw(edge_device_pages=[{"data": [EDGE_DEVICE]}]))
    ports = _nodes(batch, "Port")
    eth0 = ports[uid.port(EDGE_DEV, "eth0")].props
    assert eth0["kind"] == "phys"
    assert eth0["mac"] == _nodes(batch, "Interface")[uid.interface(EDGE_DEV, "eth0")].props["mac"]
    assert eth0["edge_device_uid"] == EDGE_DEV
    # the SSH interface is the management port
    assert ports[uid.port(EDGE_DEV, "eth7")].props["kind"] == "mgmt"
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert ("REALIZED_BY", uid.interface(EDGE_DEV, "eth0"), uid.port(EDGE_DEV, "eth0")) in rels
    assert ("ON", uid.port(EDGE_DEV, "eth0"), EDGE_DEV) in rels
    assert ("ON", uid.interface(EDGE_DEV, "eth0"), EDGE_DEV) in rels


def test_a_bound_devices_interfaces_and_ports_are_on_no_device_until_the_reasoner_runs():
    batch = _bound({EDGE_FW: BOUND_DEV})
    assert not [r for r in batch.rels if r.rel_type == "ON"]
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert ("REALIZED_BY", uid.interface(EDGE_DEV, "eth0"), uid.port(EDGE_DEV, "eth0")) in rels
    assert _nodes(batch, "Interface")[uid.interface(EDGE_DEV, "eth0")].props["edge_device_uid"] == EDGE_DEV


def _linked(*groups: dict[str, Any]):
    return _norm(
        _raw(
            edge_device_pages=[{"data": [EDGE_DEVICE, EDGE_ROUTER_DEVICE, EDGE_HUB_DEVICE]}],
            edge_link_pages=[{"data": list(groups)}],
        )
    )


def _link_ends(batch) -> dict[str, tuple[str, str]]:
    ends: dict[str, dict[str, str]] = {}
    for r in batch.rels:
        if r.rel_type in ("A_END", "Z_END") and r.start_uid.startswith("eqx:device-link:"):
            ends.setdefault(r.start_uid, {})[r.rel_type] = r.end_uid
    return {vc: (e["A_END"], e["Z_END"]) for vc, e in ends.items()}


def test_a_device_link_of_two_members_is_one_device_link_circuit():
    batch = _linked(LINK_PAIR)
    ends = _link_ends(batch)
    hub_if = uid.interface(uid.equinix("device", EDGE_HUB), "GigabitEthernet0/2")
    rtr_if = uid.interface(uid.equinix("device", EDGE_RTR), "GigabitEthernet6")
    assert [set(pair) for pair in ends.values()] == [{hub_if, rtr_if}]
    vc = _nodes(batch, "VirtualCircuit")[next(iter(ends))].props
    assert vc["type"] == "DEVICE_LINK"
    assert vc["name"] == "XX-HOSTING"
    assert vc["state"] == "PROVISIONED"
    assert vc["redundancy"] == "primary"
    assert vc["device_link_group_uuid"] == LINK_PAIR["uuid"]
    assert "bandwidth_mbps" not in vc
    # the member is found by its interface id, stored on the interface
    assert _nodes(batch, "Interface")[hub_if].props["edge_interface_id"] == "2"


def test_a_device_link_group_is_every_pair_of_the_members_the_account_has():
    batch = _linked(LINK_GROUP)
    ends = _link_ends(batch)
    # 3 members in the device list give 3 pairs; the 4th member joins none
    assert len(ends) == 3
    members = {iface for pair in ends.values() for iface in pair}
    assert members == {
        uid.interface(uid.equinix("device", EDGE_RTR), "GigabitEthernet7"),
        uid.interface(EDGE_DEV, "eth1"),
        uid.interface(uid.equinix("device", EDGE_HUB), "GigabitEthernet0/2"),
    }
    # the slowest metro link
    assert {_nodes(batch, "VirtualCircuit")[vc].props["bandwidth_mbps"] for vc in ends} == {200}


def test_the_device_link_uids_do_not_depend_on_the_member_order():
    reordered = {**LINK_GROUP, "linkDevices": list(reversed(LINK_GROUP["linkDevices"]))}
    assert set(_link_ends(_linked(LINK_GROUP))) == set(_link_ends(_linked(reordered)))


def test_without_network_edge_pages_no_device_is_emitted():
    batch = _norm(_raw())
    assert not _nodes(batch, "Device")
    assert not _nodes(batch, "Interface")


# --- fetch ----------------------------------------------------------------------------------


def _config(**kw: Any) -> EquinixConfig:
    return EquinixConfig(auth=OAuthClientCredentials(client_id="cid", client_secret="cs"), **kw)


def _transport(edge_devices: list[dict[str, Any]], edge_links: list[dict[str, Any]] | None = None):
    calls: list[dict[str, Any]] = []

    def page(items: list[dict[str, Any]], offset: int, limit: int) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": items[offset : offset + limit],
                "pagination": {"offset": offset, "limit": limit, "total": len(items)},
            },
        )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = json.loads(request.content) if request.content else None
        calls.append({"method": request.method, "path": path, "body": body})
        if path == equinix.TOKEN_PATH:
            return httpx.Response(200, json={"access_token": "tok"})
        if path == equinix.PORTS_PATH:
            return page(PORTS, int(request.url.params["offset"]), int(request.url.params["limit"]))
        if path == equinix.CONNECTIONS_SEARCH_PATH:
            return page([CONNECTION_EDGE], body["pagination"]["offset"], body["pagination"]["limit"])
        if path == equinix.EDGE_DEVICES_PATH:
            return page(edge_devices, int(request.url.params["offset"]), int(request.url.params["limit"]))
        if path == equinix.EDGE_LINKS_PATH:
            return page(edge_links or [], int(request.url.params["offset"]), int(request.url.params["limit"]))
        raise AssertionError(f"unexpected {request.method} {path}")

    return httpx.MockTransport(handler), calls


def test_the_connection_search_is_sorted_so_the_pages_keep_their_order(monkeypatch):
    transport, calls = _transport([])
    monkeypatch.setattr(equinix, "_transport", lambda config: transport)
    EquinixCollector(_config(), None).fetch()
    search = next(c for c in calls if c["path"] == equinix.CONNECTIONS_SEARCH_PATH)
    assert search["body"]["sort"] == equinix.CONNECTIONS_SORT


def test_network_edge_is_not_read_unless_the_source_enables_it(monkeypatch):
    transport, calls = _transport([EDGE_DEVICE])
    monkeypatch.setattr(equinix, "_transport", lambda config: transport)
    raw = EquinixCollector(_config(), None).fetch()
    assert "edge_device_pages" not in raw
    assert equinix.EDGE_DEVICES_PATH not in {c["path"] for c in calls}


def test_network_edge_pages_reach_the_raw_store_without_any_credential(monkeypatch):
    nested = {**EDGE_DEVICE, "interfaces": [{**EDGE_DEVICE["interfaces"][0], "sshPassword": "x"}]}
    transport, calls = _transport([nested], [LINK_PAIR])
    monkeypatch.setattr(equinix, "_transport", lambda config: transport)
    raw = EquinixCollector(_config(network_edge=True), None).fetch()
    assert equinix.EDGE_LINKS_PATH in {c["path"] for c in calls}
    assert raw["edge_link_pages"][0]["data"][0]["groupName"] == "XX-HOSTING"
    text = json.dumps(raw["edge_device_pages"])
    assert "vendorConfig" not in text and "adminPassword" not in text
    assert "sshPassword" not in text and "not-a-real-password" not in text
    assert raw["edge_device_pages"][0]["data"][0]["name"] == "XX-EDGE-FW-01"
    assert raw["edge_device_pages"][0]["data"][0]["interfaces"][0]["name"] == "eth0"


# --- Network Edge sections, virtual device circuits, binding warnings ---------------------------


def _refusing(status_for_path):
    transport, calls = _transport([EDGE_DEVICE], [LINK_PAIR])

    def handler(request):
        status = status_for_path.get(request.url.path)
        if status:
            return httpx.Response(status, json={})
        return transport.handle_request(request)

    return httpx.MockTransport(handler), calls


def test_a_refused_network_edge_device_read_keeps_the_fabric_sections(monkeypatch):
    from hst.app import runs_exec
    from hst.core.model import section_verdict

    transport, _calls = _refusing({equinix.EDGE_DEVICES_PATH: 403})
    monkeypatch.setattr(equinix, "_transport", lambda config: transport)
    collector = EquinixCollector(_config(network_edge=True), None)
    raw = collector.fetch()
    assert raw["port_pages"] and "edge_device_pages" not in raw
    assert raw["section_errors"]["network_edge_devices"] == {
        "status": 403,
        "detail": "HTTP 403 for /ne/v1/devices",
    }
    batch = collector.normalize(raw)
    assert _nodes(batch, "FabricPort")
    assert batch.sections["network_edge_devices"].status == "unauthorized"
    # `connections` fails with the device read.
    assert batch.sections["connections"].status == "failed"
    assert section_verdict(batch.sections, EquinixCollector.AUTHORITATIVE_SECTIONS) == "failed"
    assert sorted(runs_exec._failed_section_labels(collector, batch.sections)) == [
        "Device",
        "Interface",
        "Port",
        "VirtualCircuit",
    ]


def test_a_failed_device_link_read_fails_connections_so_the_circuits_carry(monkeypatch):
    """`connections` owns the VirtualCircuit of a device link."""
    from hst.app import runs_exec

    transport, _calls = _refusing({equinix.EDGE_LINKS_PATH: 500})
    monkeypatch.setattr(equinix, "_transport", lambda config: transport)
    collector = EquinixCollector(_config(network_edge=True), None)
    batch = collector.normalize(collector.fetch())
    assert batch.sections["network_edge_links"].status == "failed"
    assert batch.sections["connections"].status == "failed"
    assert "network_edge_links" in batch.sections["connections"].detail
    assert runs_exec._failed_section_labels(collector, batch.sections) == ["VirtualCircuit"]


def test_the_network_edge_sections_count_their_items(monkeypatch):
    transport, _calls = _transport([EDGE_DEVICE], [])
    monkeypatch.setattr(equinix, "_transport", lambda config: transport)
    collector = EquinixCollector(_config(network_edge=True), None)
    batch = collector.normalize(collector.fetch())
    assert batch.sections["network_edge_devices"].status == "ok"
    assert batch.sections["network_edge_devices"].row_count == 1
    assert batch.sections["network_edge_links"].status == "empty"


def test_with_network_edge_the_search_also_asks_for_the_virtual_device_circuits(monkeypatch):
    transport, calls = _transport([EDGE_DEVICE])
    monkeypatch.setattr(equinix, "_transport", lambda config: transport)
    raw = EquinixCollector(_config(network_edge=True), None).fetch()
    searches = [c for c in calls if c["path"] == equinix.CONNECTIONS_SEARCH_PATH]
    edge_search = [
        s
        for s in searches
        if s["body"]["filter"]["or"][0]["property"] == equinix.A_SIDE_VIRTUAL_DEVICE_PROPERTY
    ]
    assert edge_search
    clauses = edge_search[0]["body"]["filter"]["or"]
    assert [c["property"] for c in clauses] == [
        equinix.A_SIDE_VIRTUAL_DEVICE_PROPERTY,
        equinix.Z_SIDE_VIRTUAL_DEVICE_PROPERTY,
    ]
    assert all(c["values"] == [EDGE_FW] for c in clauses)
    assert "edge_connection_pages" in raw


def test_a_circuit_both_searches_return_is_one_node():
    batch = _norm(
        _raw(edge_device_pages=[{"data": [EDGE_DEVICE]}], edge_connection_pages=[{"data": [CONNECTION_EDGE]}])
    )
    circuits = [
        n for n in batch.nodes if n.label == "VirtualCircuit" and n.props["connection_uuid"] == CONN_EDGE
    ]
    assert len(circuits) == 1
    ends = [r for r in batch.rels if r.start_uid == circuits[0].uid and r.rel_type in ("A_END", "Z_END")]
    assert sorted(r.rel_type for r in ends) == ["A_END", "Z_END"]


def test_a_refused_virtual_device_search_is_a_section_outcome(monkeypatch):
    transport, _calls = _transport([EDGE_DEVICE])

    def handler(request):
        body = json.loads(request.content) if request.content else None
        if (
            body
            and "filter" in body
            and body["filter"]["or"][0]["property"] == equinix.A_SIDE_VIRTUAL_DEVICE_PROPERTY
        ):
            return httpx.Response(403, json={})
        return transport.handle_request(request)

    monkeypatch.setattr(equinix, "_transport", lambda config: httpx.MockTransport(handler))
    collector = EquinixCollector(_config(network_edge=True), None)
    raw = collector.fetch()
    batch = collector.normalize(raw)
    assert batch.sections["network_edge_connections"].status == "unauthorized"
    assert raw["connection_pages"]


def test_an_edge_binding_that_matches_no_device_is_a_warning():
    batch = _bound({"no-such-device": BOUND_DEV})
    assert (
        "edge_device_bindings names no-such-device, which matches no Network Edge device of the account"
        in (batch.warnings)
    )


def test_an_edge_binding_uuid_matches_in_any_case():
    assert _bound_uid({EDGE_FW.upper(): BOUND_DEV}) == BOUND_DEV


def test_two_devices_bound_to_one_device_is_a_warning():
    other = {**EDGE_DEVICE, "uuid": EDGE_RTR, "name": "XX-EDGE-RTR-01", "hostName": "XX-EDGE-RTR-01"}
    batch = normalize_equinix(
        _raw(edge_device_pages=[{"data": [EDGE_DEVICE, other]}]),
        scope="equinix:test",
        ibx_sites={},
        port_bindings={},
        edge_device_bindings={EDGE_FW: BOUND_DEV, EDGE_RTR: BOUND_DEV},
    )
    assert any("are bound to the same device" in w and BOUND_DEV in w for w in batch.warnings)


def test_no_edge_binding_warning_when_the_device_read_failed():
    raw = _raw(
        section_errors={"network_edge_devices": {"status": 403, "detail": "HTTP 403 for /ne/v1/devices"}}
    )
    batch = normalize_equinix(
        raw, scope="equinix:test", ibx_sites={}, port_bindings={}, edge_device_bindings={"x": BOUND_DEV}
    )
    assert not [w for w in batch.warnings if "edge_device_bindings" in w]
