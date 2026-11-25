"""Nautobot intent collector."""

import json

import httpx

from hst.collectors import nautobot as nb
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.collectors.nautobot import NautobotCollector, NautobotConfig, normalize_nautobot
from hst.core import Settings
from hst.core import uid as uidmod
from hst.core.identity import MemoryResolver

RAW = {
    "locations": [
        {"id": "L1", "name": "Home", "location_type": {"name": "Site"}, "parent": None},
        {
            "id": "L2",
            "name": "Office",
            "location_type": {"name": "Room"},
            "parent": {"id": "L1", "name": "Home"},
        },
        {"id": "L3", "name": "Garage", "location_type": {"name": "Site"}, "parent": None},
    ],
    "racks": [
        {"id": "R1", "name": "lab-rack", "location": {"name": "Home"}},
    ],
    "devices": [
        {
            "id": "D1",
            "name": "usw-lite-16",
            "serial": "SN00AABB01",
            "asset_tag": None,
            "position": 1,
            "status": {"name": "Active"},
            "role": {"name": "Switch"},
            "platform": {"name": "UniFi OS"},
            "device_type": {"model": "USW-Lite-16-PoE", "manufacturer": {"name": "Ubiquiti"}},
            "location": {"name": "Office"},
            "rack": {"name": "lab-rack", "location": {"name": "Home"}},
            "primary_ip4": {"address": "192.168.1.5/24"},
            "interfaces": [
                {
                    "name": f"Port {i}",
                    "type": "1000base-t",
                    "enabled": True,
                    "mgmt_only": False,
                    "mac_address": None,
                    "description": None,
                }
                for i in range(1, 5)
            ],
        },
        {
            "id": "D2",
            "name": "u6-lite",
            "serial": "SN00AABB02",
            "asset_tag": None,
            "position": None,
            "status": {"name": "Active"},
            "role": {"name": "Access Point"},
            "platform": None,
            "device_type": {"model": "U6-Lite", "manufacturer": {"name": "Ubiquiti"}},
            "location": {"name": "Office"},
            "rack": None,
            "primary_ip4": {"address": "192.168.1.6/24"},
            "interfaces": [
                {
                    "name": "Port 0",
                    "type": "1000base-t",
                    "enabled": True,
                    "mgmt_only": False,
                    "mac_address": "aa:bb:cc:00:00:02",
                    "description": "uplink",
                },
            ],
        },
        {
            "id": "D3",
            "name": "vyos-rtr",
            "serial": "VY-SN-0001",
            "asset_tag": "A-100",
            "position": None,
            "status": {"name": "Active"},
            "role": {"name": "Router"},
            "platform": {"name": "VyOS"},
            "device_type": {"model": "Generic PC", "manufacturer": {"name": "Custom"}},
            "location": {"name": "Home"},
            "rack": None,
            "primary_ip4": {"address": "192.168.1.1/24"},
            "interfaces": [
                {
                    "name": "eth0",
                    "type": "1000base-t",
                    "enabled": True,
                    "mgmt_only": False,
                    "mac_address": None,
                    "description": None,
                },
                {
                    "name": "eth1",
                    "type": "1000base-t",
                    "enabled": True,
                    "mgmt_only": False,
                    "mac_address": None,
                    "description": None,
                },
                # virtual interface: no Port node
                {
                    "name": "wg0",
                    "type": "virtual",
                    "enabled": True,
                    "mgmt_only": False,
                    "mac_address": None,
                    "description": None,
                },
            ],
        },
        {
            # documented but serial-less and role-less: kept, keyed by name
            "id": "D4",
            "name": "cable-modem",
            "serial": None,
            "asset_tag": None,
            "position": None,
            "status": {"name": "Active"},
            "role": None,
            "platform": None,
            "device_type": None,
            "location": {"name": "Garage"},
            "rack": None,
            "primary_ip4": None,
            "interfaces": [],
        },
    ],
    "cables": [
        {  # switch to router
            "id": "C1",
            "status": {"name": "Connected"},
            "terminations": [
                {
                    "termination": {
                        "__typename": "InterfaceType",
                        "name": "Port 1",
                        "device": {"name": "usw-lite-16", "serial": "SN00AABB01"},
                    }
                },
                {
                    "termination": {
                        "__typename": "InterfaceType",
                        "name": "eth1",
                        "device": {"name": "vyos-rtr", "serial": "VY-SN-0001"},
                    }
                },
            ],
        },
        {  # switch to AP
            "id": "C2",
            "status": {"name": "Connected"},
            "terminations": [
                {
                    "termination": {
                        "__typename": "InterfaceType",
                        "name": "Port 2",
                        "device": {"name": "usw-lite-16", "serial": "SN00AABB01"},
                    }
                },
                {
                    "termination": {
                        "__typename": "InterfaceType",
                        "name": "Port 0",
                        "device": {"name": "u6-lite", "serial": "SN00AABB02"},
                    }
                },
            ],
        },
        {  # 3-termination breakout (3.2): skipped
            "id": "C3",
            "status": {"name": "Connected"},
            "terminations": [
                {
                    "termination": {
                        "__typename": "InterfaceType",
                        "name": "Port 3",
                        "device": {"name": "usw-lite-16", "serial": "SN00AABB01"},
                    }
                },
                {
                    "termination": {
                        "__typename": "InterfaceType",
                        "name": "eth0",
                        "device": {"name": "vyos-rtr", "serial": "VY-SN-0001"},
                    }
                },
                {
                    "termination": {
                        "__typename": "InterfaceType",
                        "name": "Port 0",
                        "device": {"name": "u6-lite", "serial": "SN00AABB02"},
                    }
                },
            ],
        },
        {  # circuit termination: skipped
            "id": "C4",
            "status": {"name": "Connected"},
            "terminations": [
                {
                    "termination": {
                        "__typename": "InterfaceType",
                        "name": "eth0",
                        "device": {"name": "vyos-rtr", "serial": "VY-SN-0001"},
                    }
                },
                {"termination": {"__typename": "CircuitTerminationType"}},
            ],
        },
        {  # The far side is not collected.
            "id": "C5",
            "status": {"name": "Connected"},
            "terminations": [
                {
                    "termination": {
                        "__typename": "InterfaceType",
                        "name": "Port 4",
                        "device": {"name": "usw-lite-16", "serial": "SN00AABB01"},
                    }
                },
                {
                    "termination": {
                        "__typename": "InterfaceType",
                        "name": "eth0",
                        "device": {"name": "old-fw", "serial": "OLDFW123"},
                    }
                },
            ],
        },
    ],
}

# minted by the in-memory registry from the device names in RAW
SW = "dev:usw-lite-16"
AP = "dev:u6-lite"
RT = "dev:vyos-rtr"


def _cfg(**over):
    base = {
        "url": "https://nautobot.example",
        "auth": {"method": "api_key", "key": "tok"},
        "site_code": "lab",
        "site_map": {"Home": "home"},
    }
    base.update(over)
    return NautobotConfig(**base)


def _norm(raw=None, resolver=None):
    return normalize_nautobot(raw or RAW, host="nautobot.example", resolver=resolver)


def test_uid_builders():
    assert uidmod.rack("home", "lab-rack") == "rack:home:lab-rack"
    # the registry keys the switch by its serial, so another source that
    # reports the serial (UniFi) resolves to the same Device
    registry = MemoryResolver()
    _norm(resolver=registry)
    assert registry.resolve_device("serial", "sn00aabb01", "rack-switch") == SW


def test_scope():
    c = NautobotCollector(_cfg(), Settings(_env_file=None))
    assert c.scope == "nautobot:nautobot-example"


def test_each_device_reports_its_nautobot_location_and_places_none_itself():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    assert not [n for n in batch.nodes if n.label == "Site"]
    assert not [r for r in batch.rels if r.rel_type == "LOCATED_IN"]
    assert nodes[SW].props["reported_location"] == "L2"  # Office
    assert nodes[SW].props["reported_location_name"] == "Office"
    modem = nodes["dev:cable-modem"]
    assert modem.props["reported_location"] == "L3"  # Garage


def test_rack_and_in_rack():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    assert nodes["rack:l1:lab-rack"].label == "Rack"
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert ("IN_RACK", SW, "rack:l1:lab-rack") in rels


def test_rack_name_collision_across_sites_stays_two_racks():
    """Rack identity is keyed by (location id, rack name)."""
    raw = {
        "locations": [
            {"id": "L1", "name": "Home", "location_type": {"name": "Site"}, "parent": None},
            {"id": "L2", "name": "Garage", "location_type": {"name": "Site"}, "parent": None},
        ],
        "racks": [
            {"id": "R1", "name": "R1", "location": {"name": "Home"}},
            {"id": "R2", "name": "R1", "location": {"name": "Garage"}},
        ],
        "devices": [
            {
                "id": "D1",
                "name": "home-dev",
                "serial": "HOMESN01",
                "asset_tag": None,
                "position": None,
                "status": {"name": "Active"},
                "role": {"name": "Switch"},
                "platform": None,
                "device_type": {"model": "M", "manufacturer": {"name": "V"}},
                "location": {"name": "Home"},
                "rack": {"name": "R1", "location": {"name": "Home"}},
                "primary_ip4": None,
                "interfaces": [],
            },
            {
                "id": "D2",
                "name": "garage-dev",
                "serial": "GARAGESN01",
                "asset_tag": None,
                "position": None,
                "status": {"name": "Active"},
                "role": {"name": "Switch"},
                "platform": None,
                "device_type": {"model": "M", "manufacturer": {"name": "V"}},
                "location": {"name": "Garage"},
                "rack": {"name": "R1", "location": {"name": "Garage"}},
                "primary_ip4": None,
                "interfaces": [],
            },
        ],
    }
    batch = normalize_nautobot(raw, host="nautobot.example")
    rack_nodes = {n.uid for n in batch.nodes if n.label == "Rack"}
    assert rack_nodes == {uidmod.rack("L1", "R1"), uidmod.rack("L2", "R1")}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    home_dev = "dev:home-dev"
    garage_dev = "dev:garage-dev"
    assert ("IN_RACK", home_dev, uidmod.rack("L1", "R1")) in rels
    assert ("IN_RACK", garage_dev, uidmod.rack("L2", "R1")) in rels


def test_device_uids_and_props():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    sw = nodes[SW]
    assert sw.props["hostname"] == "usw-lite-16"
    assert sw.props["role"] == "switch"
    assert sw.props["vendor"] == "ubiquiti"
    assert sw.props["model"] == "USW-Lite-16-PoE"
    assert sw.props["status"] == "active"
    assert sw.props["mgmt_ip"] == "192.168.1.5"  # mask stripped
    assert nodes[RT].props["serial"] == "VY-SN-0001"


def test_serialless_device_gets_by_ref_uid_and_unknown_role():
    registry = MemoryResolver()
    batch = _norm(resolver=registry)
    nodes = {n.uid: n for n in batch.nodes}
    modem = nodes["dev:cable-modem"]
    # the registry keys a device without a serial by its name under nautobot
    assert registry.resolve_device("ref", "nautobot:cable-modem", None) == modem.uid
    assert modem.props["role"] == "unknown"  # Device requires a non-empty role


def test_port_uid_alignment():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    # unifi builds f"{duid}/port/port{idx}"; "Port 1" must slug to the same segment
    assert f"{SW}/port/port1" in nodes
    assert ("ON", f"{SW}/port/port1", SW) in rels
    assert f"{AP}/port/port0" in nodes
    # vyos-native names pass through
    assert f"{RT}/port/eth1" in nodes
    # virtual interfaces emit no Port
    assert f"{RT}/port/wg0" not in nodes


def test_cable_edges_sorted_and_keyed():
    batch = _norm()
    cables = [r for r in batch.rels if r.rel_type == "CONNECTED_TO"]
    for r in cables:
        assert r.start_uid < r.end_uid  # canonical direction: lower uid = start
        assert r.key == {"source": "nautobot-cable"}
    ends = {(r.start_uid, r.end_uid) for r in cables}
    assert (f"{SW}/port/port1", f"{RT}/port/eth1") in ends
    assert (f"{AP}/port/port0", f"{SW}/port/port2") in ends


def test_breakout_and_circuit_cables_skipped(caplog):
    batch = _norm()
    cables = [r for r in batch.rels if r.rel_type == "CONNECTED_TO"]
    assert len(cables) == 3  # C1, C2 and the dangling C5; C3 (breakout) and C4 (circuit) skipped
    assert "skipped 2 cable(s)" in caplog.text


def test_dangling_cable_emits_edge_without_nodes():
    batch = _norm()
    old_fw_port = "dev:old-fw/port/eth0"
    ends = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "CONNECTED_TO"}
    assert (old_fw_port, f"{SW}/port/port4") in ends  # the two ends in sorted order
    # The loader drops the rel.
    assert old_fw_port not in {n.uid for n in batch.nodes}
    assert "dev:old-fw" not in {n.uid for n in batch.nodes}


def test_probe_and_fetch(monkeypatch):
    monkeypatch.setattr(nb, "PAGE", 2)  # prove the offset loop with small pages

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Token tok"
        if request.url.path == "/api/status/":
            return httpx.Response(200, json={"nautobot-version": "3.2.1"})
        assert request.url.path == "/api/graphql"
        body = json.loads(request.content)
        q, offset = body["query"], body["variables"]["offset"]
        assert body["variables"]["limit"] == 2
        if "ip_addresses(" in q:
            return httpx.Response(200, json={"data": {"ip_addresses": []}})
        for field in ("locations", "racks", "devices", "cables"):
            if f"{field}(" in q:
                return httpx.Response(200, json={"data": {field: RAW[field][offset : offset + 2]}})
        raise AssertionError(f"unexpected query {q[:80]}")

    monkeypatch.setattr("hst.collectors.nautobot._transport", lambda config: httpx.MockTransport(handler))
    c = NautobotCollector(_cfg(), Settings(_env_file=None))
    assert "3.2.1" in c.probe()
    raw = c.fetch()
    assert set(raw) == {"locations", "racks", "devices", "cables", "ip_addresses", RAW_OUTCOMES_KEY}
    assert raw[RAW_OUTCOMES_KEY]["ipam:addresses"] == {"status": "empty", "row_count": 0}
    # 4 devices at page size 2 exercises a full page then a short page
    assert [d["id"] for d in raw["devices"]] == ["D1", "D2", "D3", "D4"]
    assert [x["id"] for x in raw["cables"]] == ["C1", "C2", "C3", "C4", "C5"]


def test_graphql_errors_raise(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": None, "errors": [{"message": "bad field"}]})

    monkeypatch.setattr("hst.collectors.nautobot._transport", lambda config: httpx.MockTransport(handler))
    c = NautobotCollector(_cfg(), Settings(_env_file=None))
    try:
        c.fetch()
        raise AssertionError("expected RuntimeError")
    except RuntimeError as e:
        assert "bad field" in str(e)


def _fetch_with_ipam(monkeypatch, ipam_response):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        q, offset = body["query"], body["variables"]["offset"]
        if "ip_addresses(" in q:
            return ipam_response
        for field in ("locations", "racks", "devices", "cables"):
            if f"{field}(" in q:
                return httpx.Response(200, json={"data": {field: RAW[field][offset : offset + 2]}})
        raise AssertionError(f"unexpected query {q[:80]}")

    monkeypatch.setattr("hst.collectors.nautobot._transport", lambda config: httpx.MockTransport(handler))
    c = NautobotCollector(_cfg(), Settings(_env_file=None))
    return c, c.fetch()


def test_normalize_accepts_what_fetch_records_for_ipam(monkeypatch):
    c, raw = _fetch_with_ipam(monkeypatch, httpx.Response(200, json={"data": {"ip_addresses": []}}))
    assert c.normalize(raw).sections["ipam:addresses"].status == "empty"
    row = {"id": "IP1", "address": "10.0.0.1/24"}
    c, raw = _fetch_with_ipam(monkeypatch, httpx.Response(200, json={"data": {"ip_addresses": [row]}}))
    assert c.normalize(raw).sections["ipam:addresses"].status == "ok"


def test_failed_ipam_read_normalizes_as_failed_section(monkeypatch):
    c, raw = _fetch_with_ipam(
        monkeypatch, httpx.Response(200, json={"data": None, "errors": [{"message": "no ipam"}]})
    )
    section = c.normalize(raw).sections["ipam:addresses"]
    assert section.status == "failed"
    assert "no ipam" in section.detail


def test_normalize_maps_ipam_outcomes_stored_before_the_status_vocabulary():
    for stored, expected in (("complete", "ok"), ("incomplete", "failed")):
        raw = {**RAW, RAW_OUTCOMES_KEY: {"ipam:addresses": {"status": stored, "row_count": 1}}}
        assert _norm(raw).sections["ipam:addresses"].status == expected
