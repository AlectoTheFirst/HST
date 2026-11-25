"""UniFi clients at scale."""

from __future__ import annotations

import copy

from tests.test_unifi import RAW

from hst.collectors.unifi import UnifiCollector, UnifiConfig
from hst.core import Settings, uid
from hst.core.config import DEFAULT_L2_FABRIC

AUTH = {"method": "user_password", "username": "ro", "password": "pw"}


def _collector(**config):
    return UnifiCollector(
        UnifiConfig(url="https://c", auth=AUTH, source_name="unifi-home", **config),
        Settings(_env_file=None),
    )


def test_the_default_keeps_every_client_in_the_graph_and_writes_no_side_table():
    collector = _collector()
    assert collector.config.include_clients is True
    batch = collector.normalize(copy.deepcopy(RAW))
    endpoints = {n.uid for n in batch.nodes if n.label == "Endpoint"}
    assert endpoints == {
        "ep:unifi:unifi-home:default:aabbcc999999",
        "ep:unifi:unifi-home:default:112233445566",
        "ep:unifi:unifi-home:default:778899aabbcc",
        "ep:unifi:unifi-home:default:deadbeef0001",
        "ep:unifi:unifi-home:default:deadbeef0002",
    }
    assert collector.side_tables(RAW) == {}


def test_without_clients_in_the_graph_the_wired_clients_are_mac_rows():
    collector = _collector(include_clients=False)
    batch = collector.normalize(copy.deepcopy(RAW))
    assert not any(n.label == "Endpoint" for n in batch.nodes)
    rows = collector.side_tables(RAW)["mac"]
    devices = {n.uid for n in batch.nodes if n.label == "Device"}
    ports = {n.uid for n in batch.nodes if n.label == "Port"}
    switch = next(n.uid for n in batch.nodes if n.label == "Device" and n.props.get("serial") == "SW1234567")
    assert sorted(rows, key=lambda r: r["port_name"]) == [
        {
            "device_uid": switch,
            "vlan": 1,
            "mac": "aabbcc999999",
            "port_name": "port1",
            "bridge_domain_uid": uid.bridge_domain(DEFAULT_L2_FABRIC, 1),
        },
        {
            "device_uid": switch,
            "vlan": 1,
            "mac": "112233445566",
            "port_name": "port3",
            "bridge_domain_uid": uid.bridge_domain(DEFAULT_L2_FABRIC, 1),
        },
    ]
    # each row names a Device and a Port the batch holds
    for row in rows:
        assert row["device_uid"] in devices
        assert uid.port(row["device_uid"], row["port_name"]) in ports


def test_a_client_on_no_collected_port_or_with_a_malformed_port_has_no_row():
    raw = copy.deepcopy(RAW)
    raw["clients"] = [
        {"mac": "02:00:00:00:00:01", "is_wired": True, "sw_mac": "aa:bb:cc:00:00:01", "sw_port": 42},
        {"mac": "02:00:00:00:00:02", "is_wired": True, "sw_mac": "aa:bb:cc:00:00:01", "sw_port": "x"},
        {"mac": "02:00:00:00:00:03", "is_wired": True, "sw_mac": "ff:ff:ff:00:00:09", "sw_port": 2},
        {
            "mac": "02:00:00:00:00:04",
            "is_wired": True,
            "sw_mac": "aa:bb:cc:00:00:01",
            "sw_port": 2,
            "vlan": 30,
        },
    ]
    rows = _collector(include_clients=False).side_tables(raw)["mac"]
    assert [(r["mac"], r["port_name"], r["vlan"]) for r in rows] == [("020000000004", "port2", 30)]
