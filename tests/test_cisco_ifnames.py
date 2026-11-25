"""`show vrf` abbreviates member interface names; `show interfaces`, `show ip
arp`, route output, LLDP/CDP and the FHRP summaries each print their own spelling. The VRF joins, the
neighbor, FHRP and route rows and the side-store interface columns must agree
on the spelling of the device's own interface table."""

import json

import pytest
from tests import test_iosxr, test_nxos
from tests.test_cisco_common import DEV as COMMON_DEV
from tests.test_cisco_common import INTER, L3DOM, SCOPE, SOURCE
from tests.test_iosxe import DEV, FULL_NAME_VRF_TEXT, RAW, _collector

from hst.collectors import cisco_common, iosxe, iosxr, nxos
from hst.core import uid
from hst.core.normalize import IfNameResolver

# as the device prints it: members abbreviated
ABBREVIATED_VRF_TEXT = """\
  Name                             Default RD            Protocols   Interfaces
  mgmt                             <not set>             ipv4        Vl10
                                                                       Gi1/0/2
"""


def _abbreviated_raw():
    cmd_vrf = next(k for k, v in RAW.items() if v.lstrip().startswith("Name") and "mgmt" in v)
    return {**RAW, cmd_vrf: ABBREVIATED_VRF_TEXT}


def test_if_vrf_map_keys_by_slug():
    out = cisco_common.if_vrf_map([{"name": "mgmt", "interfaces": ["Vl10", "Gi1/0/2"]}], vrf_key="name")
    assert out == {"vlan10": "mgmt", "gi1-0-2": "mgmt"}


def test_iosxe_abbreviated_show_vrf_places_interface_and_arp_in_the_vrf():
    inter = iosxe.parse(_abbreviated_raw())
    svi = next(i for i in inter["interfaces"] if i["name"] == "Vlan10")
    assert svi["ips"] == [{"ip": "10.10.10.1", "prefixlen": 24, "vrf": "mgmt"}]
    arp = next(a for a in inter["arp"] if a["ip"] == "10.255.0.2")
    assert arp["vrf"] == "mgmt"


def test_iosxe_fixture_prints_show_vrf_as_the_device_does_and_parses_as_the_full_names_do():
    assert "Vl10" in RAW[iosxe.CMD_VRF] and "Vlan10" not in RAW[iosxe.CMD_VRF]
    full = iosxe.parse({**RAW, iosxe.CMD_VRF: FULL_NAME_VRF_TEXT})
    short = iosxe.parse(RAW)
    assert short["interfaces"] == full["interfaces"]
    assert short["arp"] == full["arp"]
    assert next(a for a in short["arp"] if a["ip"] == "10.255.0.2")["vrf"] == "mgmt"


def test_iosxe_abbreviated_show_vrf_puts_the_svi_in_the_vrf_instance():
    batch = _collector().normalize(_abbreviated_raw())
    iu = uid.interface(DEV, "Vlan10")
    vru = uid.vrf(DEV, "mgmt")
    assert any(r.rel_type == "IN_VRF" and r.start_uid == iu and r.end_uid == vru for r in batch.rels)


def test_side_rows_spell_abbreviated_route_and_arp_interfaces_as_the_interface_table():
    inter = iosxe.parse(RAW)
    inter["rib"] = [{**inter["rib"][0], "interface": "Gi1/0/1"}]
    inter["arp"] = [{**inter["arp"][0], "interface_name": "Gi1/0/1"}]
    rows = cisco_common.side_rows(inter, DEV)
    assert [r["interface"] for r in rows["rib"]] == ["GigabitEthernet1/0/1"]
    assert [r["interface_name"] for r in rows["arp"]] == ["GigabitEthernet1/0/1"]


def test_side_rows_keep_an_exact_interface_name_when_another_shares_its_slug():
    inter = iosxe.parse(RAW)
    inter["interfaces"] = [
        *inter["interfaces"],
        {"name": "GigabitEthernet0/0.1", "ips": []},
        {"name": "GigabitEthernet0/0/1", "ips": []},
    ]
    inter["rib"] = [{**inter["rib"][0], "interface": "GigabitEthernet0/0.1"}]
    rows = cisco_common.side_rows(inter, DEV)
    assert [r["interface"] for r in rows["rib"]] == ["GigabitEthernet0/0.1"]


def test_if_vrf_map_resolves_members_the_slug_alone_does_not_match():
    """`Fi`, `BE` and `Mg` slug differently from the full names; the
    members are resolved against the interface table first."""
    names = ["FiveGigabitEthernet1/0/1", "Bundle-Ether10", "MgmtEth0/RP0/CPU0/0", "Vlan10"]
    rows = [{"name": "mgmt", "interfaces": ["Fi1/0/1", "BE10", "Mg0/RP0/CPU0/0", "Vl10"]}]
    out = cisco_common.if_vrf_map(rows, vrf_key="name", device_ifnames=names)
    resolve = IfNameResolver(names)
    for name in names:
        assert cisco_common.vrf_of(out, resolve, name, "") == "mgmt"
    assert cisco_common.vrf_of(out, resolve, "GigabitEthernet9/9", "") == ""
    assert cisco_common.vrf_of(out, resolve, None, "default") == "default"


def test_if_vrf_map_keeps_a_subinterface_and_a_slot_in_their_own_vrfs():
    names = ["GigabitEthernet0/0.1", "GigabitEthernet0/0/1"]
    rows = [{"name": "A", "interfaces": ["Gi0/0.1"]}, {"name": "B", "interfaces": ["Gi0/0/1"]}]
    out = cisco_common.if_vrf_map(rows, vrf_key="name", device_ifnames=names)
    resolve = IfNameResolver(names)
    assert cisco_common.vrf_of(out, resolve, "GigabitEthernet0/0.1", "") == "A"
    assert cisco_common.vrf_of(out, resolve, "GigabitEthernet0/0/1", "") == "B"
    assert uid.interface(DEV, names[0]) != uid.interface(DEV, names[1])


def _interface(name, kind, mac=None, ips=()):
    return {"name": name, "kind": kind, "mac": mac, "admin_up": True, "ips": list(ips), "vlan": None}


def test_neighbors_printed_abbreviated_land_on_the_ports_of_the_interface_table():
    inter = {
        **INTER,
        "interfaces": [
            _interface("FiveGigabitEthernet1/0/1", "phys", "aabbccddee21"),
            _interface("Bundle-Ether10", "phys", "aabbccddee22"),
            _interface("MgmtEth0/RP0/CPU0/0", "mgmt", "aabbccddee23"),
        ],
        "neighbors": [
            {"local_port": "Fi1/0/1", "name": "a", "mac": "aabbccddef11", "port": "Gi1/0/1", "proto": "lldp"},
            {"local_port": "BE10", "name": "b", "mac": None, "port": "BE20", "proto": "cdp"},
            {
                "local_port": "Mg0/RP0/CPU0/0",
                "name": "c",
                "mac": "aabbccddef13",
                "port": "mgmt0",
                "proto": "lldp",
            },
        ],
    }
    batch = cisco_common.normalize_cisco(inter, source=SOURCE, scope=SCOPE, l3dom=L3DOM)

    def port(name):
        return next(n for n in batch.nodes if n.uid == uid.port(COMMON_DEV, name) and n.label == "Port")

    assert port("FiveGigabitEthernet1/0/1").props["lldp_neighbor_name"] == "a"
    # the far end's port is kept as the device printed it
    assert port("FiveGigabitEthernet1/0/1").props["lldp_neighbor_port"] == "Gi1/0/1"
    assert port("Bundle-Ether10").props["cdp_neighbor_name"] == "b"
    assert port("MgmtEth0/RP0/CPU0/0").props["lldp_neighbor_name"] == "c"


def test_trunk_membership_printed_abbreviated_carries_the_vlan_on_the_port():
    inter = {
        **INTER,
        "interfaces": [_interface("FiveGigabitEthernet1/0/1", "phys", "aabbccddee21")],
        "neighbors": [],
        "vlan_ports": {"10": ["Fi1/0/1"]},
    }
    batch = cisco_common.normalize_cisco(inter, source=SOURCE, scope=SCOPE, l3dom=L3DOM)
    pu = uid.port(COMMON_DEV, "FiveGigabitEthernet1/0/1")
    assert any(r.rel_type == "CARRIES" and r.start_uid == pu for r in batch.rels)


def test_fhrp_rows_resolve_to_the_name_the_interface_table_spells():
    inter = {
        "interfaces": [
            {"name": "Bundle-Ether10", "ips": [{"ip": "10.0.0.1", "prefixlen": 24, "vrf": ""}]},
            {"name": "FiveGigabitEthernet1/0/1", "ips": [{"ip": "10.0.1.1", "prefixlen": 24, "vrf": ""}]},
        ],
        "fhrp": [
            {"interface": "BE10", "kind": "hsrp", "group": 1, "vip": "10.0.0.254"},
            {"interface": "Fi1/0/1", "kind": "vrrp", "group": 2, "vip": "10.0.1.254"},
            {"interface": "BE99", "kind": "hsrp", "group": 3, "vip": "10.0.9.254"},
        ],
    }
    resolved, skipped = cisco_common.resolve_fhrp(inter)
    assert [r["interface"] for r in resolved] == ["Bundle-Ether10", "FiveGigabitEthernet1/0/1"]
    assert list(skipped) == ["hsrp"]


def test_nxos_route_and_mac_rows_spell_an_abbreviated_interface_as_the_interface_table():
    """NX-OS route output prints `Eth1/1` where its interface table has
    `Ethernet1/1`; the side row must name the Interface the trace matches by
    name."""
    route = {
        "TABLE_vrf": {
            "ROW_vrf": {
                "vrf-name-out": "default",
                "TABLE_addrf": {
                    "ROW_addrf": {
                        "addrf": "ipv4",
                        "TABLE_prefix": {
                            "ROW_prefix": {
                                "ipprefix": "10.9.0.0/24",
                                "TABLE_path": {
                                    "ROW_path": {
                                        "ipnexthop": "10.0.0.5",
                                        "ifname": "Eth1/1",
                                        "clientname": "static",
                                        "pref": 1,
                                        "metric": 0,
                                    }
                                },
                            }
                        },
                    }
                },
            }
        }
    }
    inter = nxos.parse({**test_nxos.RAW, test_nxos.CMD_ROUTE: json.dumps(route)})
    assert [r["interface"] for r in inter["rib"]] == ["Eth1/1"]
    rows = cisco_common.side_rows(inter, test_nxos.DEV)
    interface_names = {i["name"] for i in inter["interfaces"]}
    assert [r["interface"] for r in rows["rib"]] == ["Ethernet1/1"]
    assert {r["interface"] for r in rows["rib"]} <= interface_names


def test_nxos_arp_row_spells_an_abbreviated_interface_as_the_interface_table():
    arp = {
        "TABLE_vrf": {
            "ROW_vrf": {
                "vrf-name-out": "default",
                "TABLE_adj": {
                    "ROW_adj": {"ip-addr-out": "10.0.0.5", "mac": "aabb.ccdd.efaa", "intf-out": "Eth1/1"}
                },
            }
        }
    }
    inter = nxos.parse({**test_nxos.RAW, test_nxos.CMD_ARP: json.dumps(arp)})
    rows = cisco_common.side_rows(inter, test_nxos.DEV)
    assert [r["interface_name"] for r in rows["arp"]] == ["Ethernet1/1"]


def test_iosxr_show_arp_row_takes_the_interface_table_name_and_its_vrf():
    """IOS-XR `show arp` abbreviates (`Gi0/0/0/0`, `Lo0`); `show vrf all detail`
    and the interface table spell the names in full."""
    text = test_iosxr.ARP_TEXT.replace("GigabitEthernet0/0/0/0", "Gi0/0/0/0").replace("Loopback0", "Lo0")
    assert text != test_iosxr.ARP_TEXT
    full = iosxr.parse(test_iosxr.RAW)
    short = iosxr.parse({**test_iosxr.RAW, test_iosxr.CMD_ARP: text})
    assert [a["vrf"] for a in short["arp"]] == [a["vrf"] for a in full["arp"]]
    assert "mgmt" in {a["vrf"] for a in short["arp"]}
    rows = cisco_common.side_rows(short, test_iosxr.DEV)
    assert [r["interface_name"] for r in rows["arp"]] == [a["interface_name"] for a in full["arp"]]
    assert [r["interface_name"] for r in rows["arp"]] == ["GigabitEthernet0/0/0/0", "Loopback0"]


def test_iosxr_route_row_spells_an_abbreviated_egress_interface_as_the_interface_table():
    text = test_iosxr.ROUTE_TEXT.replace("GigabitEthernet0/0/0/0", "Gi0/0/0/0")
    assert text != test_iosxr.ROUTE_TEXT
    inter = iosxr.parse({**test_iosxr.RAW, test_iosxr.CMD_ROUTE: text})
    assert "Gi0/0/0/0" in {r["interface"] for r in inter["rib"]}
    rows = cisco_common.side_rows(inter, test_iosxr.DEV)
    assert "GigabitEthernet0/0/0/0" in {r["interface"] for r in rows["rib"]}
    assert "Gi0/0/0/0" not in {r["interface"] for r in rows["rib"]}


def test_iosxe_lldp_row_printed_abbreviated_lands_on_the_port_of_the_interface_table():
    """The LLDP table prints `Gi1/0/1`; the parse keeps it, and the graph stage
    puts the neighbor on the Port `show interfaces` names."""
    inter = iosxe.parse(RAW)
    assert {n["local_port"] for n in inter["neighbors"] if n["proto"] == "lldp"} == {"Gi1/0/1"}
    batch = _collector().normalize(RAW)
    port = next(
        n for n in batch.nodes if n.label == "Port" and n.uid == uid.port(DEV, "GigabitEthernet1/0/1")
    )
    assert port.props["lldp_neighbor_name"] == "core1"


def test_collectors_that_mint_interface_uids_declare_the_uid_version():
    from hst.collectors import REGISTRY

    for name in ("iosxe", "iosxr", "nxos", "vyos", "nautobot", "velocloud", "checkpoint_gateway", "apic"):
        assert REGISTRY[name].NORMALIZATION_VERSIONS["iface_uid"] == uid.IFACE_UID_VERSION, name


@pytest.mark.parametrize("raw_name", ["Gi0/0.1", "Gi0/0/1"])
def test_side_rows_tell_a_subinterface_from_a_slot(raw_name):
    inter = iosxe.parse(RAW)
    inter["interfaces"] = [
        *inter["interfaces"],
        {"name": "GigabitEthernet0/0.1", "ips": []},
        {"name": "GigabitEthernet0/0/1", "ips": []},
    ]
    inter["rib"] = [{**inter["rib"][0], "interface": raw_name}]
    rows = cisco_common.side_rows(inter, DEV)
    expected = {"Gi0/0.1": "GigabitEthernet0/0.1", "Gi0/0/1": "GigabitEthernet0/0/1"}[raw_name]
    assert [r["interface"] for r in rows["rib"]] == [expected]
