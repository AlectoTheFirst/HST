"""Equinix Fabric on the map: the Fabric devices, ports, cross-connects and circuits of a run."""

from __future__ import annotations

from typing import Any

from hst.map import layout
from hst.map.tiers import bootstrap, fabric, fold

PORTS: list[dict[str, Any]] = [
    {
        "uid": "eqx:port:xa-1",
        "name": "XA-1",
        "state": "ACTIVE",
        "metro": "XA",
        "ibx": "XA2",
        "speed_mbps": 10000,
        "port": "dev:sw1/port/eth1",
        "device": "dev:sw1",
    },
    {
        "uid": "eqx:port:xa-2",
        "name": "XA-2",
        "state": "INACTIVE",
        "metro": "XA",
        "ibx": "XA2",
        "speed_mbps": 10000,
        "port": None,
        "device": None,
    },
    {
        "uid": "eqx:port:xk-1",
        "name": "XK-1",
        "state": "ACTIVE",
        "metro": "XK",
        "ibx": "XK1",
        "speed_mbps": 1000,
        "port": None,
        "device": None,
    },
]


def _circuit(uid: str, state: str = "ACTIVE", provider: str | None = None, **ends: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "uid": uid,
        "name": uid,
        "type": "EVPL",
        "state": state,
        "bandwidth_mbps": 500,
        "provider": provider,
    }
    for side in ("a", "z"):
        for key in ("end", "labels", "device", "port", "vlan"):
            row[f"{side}_{key}"] = ends.get(f"{side}_{key}")
    return row


CIRCUITS = [
    # A cross-connected estate port to an unbound Fabric port of another metro.
    _circuit(
        "vc:1",
        a_end="eqx:port:xa-1",
        a_labels=["FabricPort"],
        a_device="dev:sw1",
        a_port="dev:sw1/port/eth1",
        a_vlan=100,
        z_end="eqx:port:xk-1",
        z_labels=["FabricPort"],
        z_vlan=200,
    ),
    # An estate port to a cloud on-ramp: no Z end in the account.
    _circuit(
        "vc:2",
        provider="Azure ExpressRoute",
        a_end="eqx:port:xa-1",
        a_labels=["FabricPort"],
        a_device="dev:sw1",
        a_port="dev:sw1/port/eth1",
        a_vlan=300,
    ),
    # A provider the families do not name.
    _circuit("vc:3", provider="Provider X", a_end="eqx:port:xk-1", a_labels=["FabricPort"]),
    # The reasoner cables these two estate ports.
    _circuit(
        "vc:4",
        a_end="eqx:port:xa-1",
        a_labels=["FabricPort"],
        a_device="dev:sw1",
        a_port="dev:sw1/port/eth1",
        z_end="iface",
        z_labels=["Interface"],
        z_device="dev:ne1",
        z_port="dev:ne1/port/p1",
    ),
    _circuit("vc:5", state="DEPROVISIONED", a_end="eqx:port:xa-1", a_labels=["FabricPort"]),
]


def test_the_fabric_ports_of_a_metro_are_the_ports_of_its_fabric_device() -> None:
    out = fabric.build(PORTS, [])
    assert set(out.devices) == {"eqx:fabric:XA", "eqx:fabric:XK"}
    assert out.devices["eqx:fabric:XA"]["site"] == fabric.FABRIC_SITE
    assert out.devices["eqx:fabric:XA"]["label"] == "Fabric XA"
    assert {p["uid"]: (p["device"], p["oper"]) for p in out.ports} == {
        "eqx:port:xa-1": ("eqx:fabric:XA", "up"),
        "eqx:port:xa-2": ("eqx:fabric:XA", "down"),
        "eqx:port:xk-1": ("eqx:fabric:XK", "up"),
    }
    assert out.sites == {fabric.FABRIC_SITE: fabric.FABRIC_NAME}


def test_a_cross_connect_from_an_estate_port_to_a_fabric_port_is_a_cable() -> None:
    out = fabric.build(PORTS, [])
    assert [(c["a_dev"], c["a_port"], c["b_dev"], c["b_port"], c["source"]) for c in out.cables] == [
        ("dev:sw1", "dev:sw1/port/eth1", "eqx:fabric:XA", "eqx:port:xa-1", fabric.CROSS_CONNECT)
    ]


def test_a_circuit_ends_at_its_fabric_port_or_at_its_provider_and_an_ended_one_is_left_out() -> None:
    out = fabric.build(PORTS, CIRCUITS)
    rows = {r["uid"]: r for r in out.circuits}
    assert set(rows) == {"vc:1", "vc:2", "vc:3", "vc:4"}
    # A Fabric port cross-connected to an estate port is the end.
    assert (rows["vc:1"]["a_device"], rows["vc:1"]["a_port"], rows["vc:1"]["a_vlan"]) == (
        "eqx:fabric:XA",
        "eqx:port:xa-1",
        "100",
    )
    assert (rows["vc:1"]["z_device"], rows["vc:1"]["z_port"], rows["vc:1"]["z_vlan"]) == (
        "eqx:fabric:XK",
        "eqx:port:xk-1",
        "200",
    )
    assert (rows["vc:2"]["z_device"], rows["vc:2"]["z_port"], rows["vc:2"]["family"]) == (
        "eqx:cloud-azure",
        None,
        "Microsoft Azure",
    )
    assert rows["vc:3"]["z_device"] == "eqx:cloud-other"
    assert (rows["vc:4"]["a_device"], rows["vc:4"]["z_device"], rows["vc:4"]["cable_id"]) == (
        "eqx:fabric:XA",
        "dev:ne1",
        None,
    )
    assert out.devices["eqx:cloud-azure"]["site"] == "CLOUD-AZURE"
    assert out.sites["CLOUD-AZURE"] == "Microsoft Azure"
    assert out.sites["CLOUD-OTHER"] == "Other parties"


def test_the_provider_family_comes_from_the_service_profile_name() -> None:
    assert fabric.family("AWS Direct Connect")[0] == "CLOUD-AWS"
    assert fabric.family("Google Cloud Partner Interconnect")[0] == "CLOUD-GOOGLE"
    assert fabric.family("Oracle Cloud Infrastructure -OCI- FastConnect")[0] == "CLOUD-ORACLE"
    assert fabric.family("Akamai SIP")[0] == "CLOUD-AKAMAI"
    assert fabric.family(None) == fabric.OTHER


def test_a_fabric_port_sits_in_the_site_of_its_device_else_of_its_ibx_else_on_its_metro() -> None:
    ports = [
        {**PORTS[0], "ibx": "XB6", "device_site": "XB3", "bound_by": "name+cable"},
        {**PORTS[1], "ibx": "XC4"},
        PORTS[2],
    ]
    out = fabric.build(ports, [], ["XB3", "CH-SITE-XC4"])
    assert {p["uid"]: p["device"] for p in out.ports} == {
        "eqx:port:xa-1": "eqx:ibx:XB3:XB6",
        "eqx:port:xa-2": "eqx:ibx:CH-SITE-XC4:XC4",
        "eqx:port:xk-1": "eqx:fabric:XK",
    }
    equinix = out.devices["eqx:ibx:XB3:XB6"]
    assert (equinix["site"], equinix["label"], equinix["tier"], equinix["platform"]) == (
        "XB3",
        "Equinix XB6",
        "wan-edge",
        layout.FABRIC_PLATFORM,
    )
    assert [(c["a_dev"], c["b_dev"]) for c in out.cables] == [("dev:sw1", "eqx:ibx:XB3:XB6")]
    # The sites of the Equinix devices are estate sites, not cloud sites.
    assert out.sites == {fabric.FABRIC_SITE: fabric.FABRIC_NAME}


def test_the_ibx_site_is_the_site_with_the_ibx_code_else_the_one_whose_last_token_is_it() -> None:
    assert fabric.ibx_site("XC4", ["CH-SITE-XC4", "XC4"]) == "XC4"
    assert fabric.ibx_site("XC4", ["CH-SITE-XC4", "CH-SITE-XC5"]) == "CH-SITE-XC4"
    assert fabric.ibx_site("XK1", ["CH-SITE-XC4"]) is None
    assert fabric.ibx_site(None, ["XC4"]) is None


def test_a_circuit_ends_on_the_device_of_an_unbound_fabric_port() -> None:
    ports = [{**PORTS[1], "ibx": "XC4"}]
    circuits = [_circuit("vc:9", a_end="eqx:port:xa-2", a_labels=["FabricPort"], a_vlan=10)]
    out = fabric.build(ports, circuits, ["CH-SITE-XC4"])
    end = (out.circuits[0]["a_device"], out.circuits[0]["a_port"])
    assert end == ("eqx:ibx:CH-SITE-XC4:XC4", "eqx:port:xa-2")


def test_the_fabric_port_rows_carry_the_facts_of_the_schema_and_the_binding() -> None:
    ports = [
        {
            **PORTS[0],
            "redundancy": "primary",
            "lag_name": "ae1",
            "cable_ids": ["10000001", "10000002"],
            "bound_by": "name+cable",
        },
        {**PORTS[1], "binding": "dev:gone/port/eth1"},
        {**PORTS[2], "binding_issue": "several-ports", "binding_ports": ["dev:a/port/1", "dev:b/port/1"]},
    ]
    rows = {r["uid"]: r for r in fabric.build(ports, []).fabric_ports}
    bound = rows["eqx:port:xa-1"]
    assert (bound["redundancy"], bound["lag_name"], bound["cable_ids"]) == (
        "primary",
        "ae1",
        "10000001, 10000002",
    )
    assert (bound["bound_by"], bound["port_uid"], bound["port_device"]) == (
        "name+cable",
        "dev:sw1/port/eth1",
        "dev:sw1",
    )
    assert bound["device_uid"] == "eqx:fabric:XA"
    # An operator binding to a port that is not in the run.
    assert (rows["eqx:port:xa-2"]["binding_issue"], rows["eqx:port:xa-2"]["binding_ports"]) == (
        "binding-not-in-run",
        "dev:gone/port/eth1",
    )
    assert rows["eqx:port:xk-1"]["binding_ports"] == "dev:a/port/1, dev:b/port/1"
    assert rows["eqx:port:xk-1"]["bound_by"] is None


def test_a_bound_network_edge_device_is_not_drawn() -> None:
    rows = {
        "eqx:ne:1": {"platform": layout.NETWORK_EDGE, "bound_device_uid": "dev:hub"},
        "eqx:ne:2": {"platform": layout.NETWORK_EDGE, "bound_device_uid": None},
        "dev:hub": {"platform": "velocloud"},
    }
    assert set(fold.drawn(rows)) == {"eqx:ne:2", "dev:hub"}


def test_an_unbound_network_edge_device_with_the_hostname_of_one_other_device_draws_as_it() -> None:
    ne = layout.NETWORK_EDGE
    rows = {
        "eqx:device:1": {"label": "GB-SITE-XD1-RTH-01", "platform": ne},
        "vco:1": {"label": "GB-SITE-XD1-RTH-01", "platform": "velocloud"},
        "eqx:device:2": {"label": "UK-SITE-XD1-RTI-01", "platform": ne},
        "eqx:device:3": {"label": "TWIN-01", "platform": ne},
        "dev:a": {"label": "TWIN-01"},
        "dev:b": {"label": "twin-01"},
    }
    alias = fold.aliases(rows)
    assert alias == {"eqx:device:1": "vco:1"}
    facts = bootstrap.DeviceFacts(
        members={"eqx:device:1": {"interfaces": {"if:1"}}, "vco:1": {"interfaces": {"if:2"}}},
        ports=[{"device": "eqx:device:1", "uid": "eqx:if:1/port/p1"}],
        cables=[
            {"a_dev": "eqx:device:1", "a_port": "eqx:if:1/port/p1", "b_dev": "dev:x", "b_port": "dev:x/p"}
        ],
        tunnels=[{"device": "dev:x", "other": "eqx:device:1", "tunnel": "t", "encap": "ipsec"}],
    )
    fab = fabric.build([], [_circuit("vc:7", a_end="if", a_labels=["Interface"], a_device="eqx:device:1")])
    fold._merge(facts, fab, alias)
    assert facts.ports[0]["device"] == "vco:1"
    assert (facts.cables[0]["a_dev"], facts.tunnels[0]["other"]) == ("vco:1", "vco:1")
    assert facts.members == {"vco:1": {"interfaces": {"if:1", "if:2"}}}
    assert fab.circuits[0]["a_device"] == "vco:1"


def test_a_metro_whose_bound_ports_are_in_one_site_group_is_a_spine_in_that_group() -> None:
    ports = [
        {**PORTS[0], "ibx": "XA2", "device_site": "XA2", "bound_by": "name+cable"},
        {**PORTS[1], "ibx": "XA6", "device_site": "XA6", "port": "dev:sw6/port/eth1", "device": "dev:sw6"},
        PORTS[2],
    ]
    group = ("Area A", "Area A1")
    out = fabric.build(ports, [], ["XA2", "XA6"], {"XA2": group, "XA6": group})
    assert out.spines == {"EQUINIX-FABRIC-XA": (group, ("XA2", "XA6"))}
    assert {p["uid"]: p["device"] for p in out.ports} == {
        "eqx:port:xa-1": "eqx:fabric:XA",
        "eqx:port:xa-2": "eqx:fabric:XA",
        "eqx:port:xk-1": "eqx:fabric:XK",
    }
    assert out.devices["eqx:fabric:XA"]["site"] == "EQUINIX-FABRIC-XA"
    assert out.devices["eqx:fabric:XK"]["site"] == fabric.FABRIC_SITE
    assert [(c["a_dev"], c["b_dev"]) for c in out.cables] == [
        ("dev:sw1", "eqx:fabric:XA"),
        ("dev:sw6", "eqx:fabric:XA"),
    ]
    # With no site group that holds both sites, each site keeps its Equinix device.
    apart = fabric.build(ports, [], ["XA2", "XA6"], {"XA2": group})
    assert apart.spines == {}
    assert {p["uid"]: p["device"] for p in apart.ports}["eqx:port:xa-1"] == "eqx:ibx:XA2:XA2"


def test_a_circuit_between_two_bound_fabric_ports_ends_on_the_fabric_ports() -> None:
    ports = [
        {**PORTS[0], "ibx": "XA6", "device_site": "XA6"},
        {**PORTS[2], "ibx": "XB3", "device_site": "XB3", "port": "dev:xb3/port/eth1", "device": "dev:xb3"},
    ]
    circuits = [
        _circuit(
            "vc:8",
            a_end="eqx:port:xa-1",
            a_labels=["FabricPort"],
            a_device="dev:sw1",
            a_port="dev:sw1/port/eth1",
            z_end="eqx:port:xk-1",
            z_labels=["FabricPort"],
            z_device="dev:xb3",
            z_port="dev:xb3/port/eth1",
        )
    ]
    out = fabric.build(ports, circuits, ["XA6", "XB3"])
    row = out.circuits[0]
    assert (row["a_device"], row["a_port"]) == ("eqx:ibx:XA6:XA6", "eqx:port:xa-1")
    assert (row["z_device"], row["z_port"]) == ("eqx:ibx:XB3:XB3", "eqx:port:xk-1")
    assert row["cable_id"] is None
    assert {(c["a_dev"], c["b_dev"]) for c in out.cables} == {
        ("dev:sw1", "eqx:ibx:XA6:XA6"),
        ("dev:xb3", "eqx:ibx:XB3:XB3"),
    }


def test_the_link_the_reasoner_derives_from_a_circuit_is_no_cable_on_the_map() -> None:
    assert not fold.on_map({"source": fabric.CIRCUIT_CABLE})
    assert fold.on_map({"source": fabric.CROSS_CONNECT})
    assert fold.on_map({"source": "cdp"})


def test_a_spine_is_a_wan_edge_device_of_the_fabric_platform() -> None:
    ports = [
        {**PORTS[0], "ibx": "XA2", "device_site": "XA2"},
        {**PORTS[1], "ibx": "XA6", "device_site": "XA6", "port": "dev:sw6/port/eth1", "device": "dev:sw6"},
    ]
    group = ("Area A1",)
    out = fabric.build(ports, [], ["XA2", "XA6"], {"XA2": group, "XA6": group})
    spine = out.devices["eqx:fabric:XA"]
    assert (spine["tier"], spine["platform"]) == ("wan-edge", layout.FABRIC_PLATFORM)
    assert spine["vendor"] == "Equinix"
