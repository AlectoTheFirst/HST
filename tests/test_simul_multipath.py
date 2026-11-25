"""BGP multipath: the collectors read `maximum-paths` and `bestpath as-path
multipath-relax`, and the simulation installs the equal paths a process's
count allows beside its best one."""

from __future__ import annotations

import pytest
from tests.test_simul_rib import CTX, R1, _connected, _ctx, _path, _process, _rows, _session

from hst.collectors import iosxe, iosxr_bgp, nxos, vyos
from hst.collectors.util import GraphBuilder, bgp_multipath_props, parse_maximum_paths
from hst.simul import rib
from hst.simul.propagate import SimulationInput

PREFIX = "203.0.113.0/24"
P1, P2, P3 = "bgp:r1:p1", "bgp:r1:p2", "bgp:r1:p3"


def _equal_paths(*, as_paths=("65002", "65002", "65002"), **process):
    """R1 (AS 65001) learns 203.0.113.0/24 from three eBGP peers over three
    links, with equal attributes."""
    sessions = [
        _session(P1, "rp:r1:bgp", 65001, 65002, "10.0.1.1", "10.0.1.2"),
        _session(P2, "rp:r1:bgp", 65001, 65002, "10.0.2.1", "10.0.2.2"),
        _session(P3, "rp:r1:bgp", 65001, 65002, "10.0.3.1", "10.0.3.2"),
    ]
    paths = [
        _path(P1, PREFIX, "10.0.1.2", as_path=as_paths[0]),
        _path(P2, PREFIX, "10.0.2.2", as_path=as_paths[1]),
        _path(P3, PREFIX, "10.0.3.2", as_path=as_paths[2]),
    ]
    status = {(uid, "received"): "complete" for uid in (P1, P2, P3)}
    status.update({(uid, "accepted"): "not-captured" for uid in (P1, P2, P3)})
    return rib.RibInput(
        contexts=[_ctx()],
        connected=[
            _connected("10.0.1.0/30", "Ethernet1/1"),
            _connected("10.0.2.0/30", "Ethernet1/2"),
            _connected("10.0.3.0/30", "Ethernet1/3"),
        ],
        bgp=SimulationInput(processes=[_process("rp:r1:bgp", CTX, 65001, R1, **process)], sessions=sessions),
        observed_paths=paths,
        direction_status=status,
        platform="nxos",
    )


def _bgp_hops(result):
    return sorted(hop for prefix, protocol, hop in _rows(result) if prefix == PREFIX and protocol == "bgp")


def test_the_configured_count_installs_the_equal_paths():
    result = rib.compute(_equal_paths(**bgp_multipath_props({"ebgp_v4": 2}, False)))

    assert len(_bgp_hops(result)) == 2
    assert not [g for g in result.gaps if g.get("prefix") == PREFIX and g["kind"] == rib.NOT_OBSERVED]


def test_a_count_above_the_paths_installs_every_equal_path():
    result = rib.compute(_equal_paths(**bgp_multipath_props({"ebgp_v4": 8}, False)))

    assert _bgp_hops(result) == ["10.0.1.2", "10.0.2.2", "10.0.3.2"]


def test_the_cisco_default_installs_one_path():
    result = rib.compute(_equal_paths(**bgp_multipath_props({}, False)))

    assert len(_bgp_hops(result)) == 1
    assert not [g for g in result.gaps if g["kind"] == rib.NOT_OBSERVED]


def test_an_unrecorded_count_is_a_gap_on_the_prefix():
    result = rib.compute(_equal_paths())

    assert len(_bgp_hops(result)) == 1
    gaps = [g for g in result.gaps if g["kind"] == rib.NOT_OBSERVED and g.get("prefix") == PREFIX]
    assert len(gaps) == 1
    assert gaps[0]["scope"] == "prefix"
    assert "maximum-paths is not recorded" in gaps[0]["detail"]


def test_a_different_as_path_joins_only_with_multipath_relax():
    paths = ("65002 65010", "65002 65011", "65002 65010")
    strict = rib.compute(_equal_paths(as_paths=paths, **bgp_multipath_props({"ebgp_v4": 4}, False)))
    relaxed = rib.compute(_equal_paths(as_paths=paths, **bgp_multipath_props({"ebgp_v4": 4}, True)))

    assert len(_bgp_hops(strict)) == 2
    assert len(_bgp_hops(relaxed)) == 3


def test_the_ibgp_count_does_not_apply_to_ebgp_paths():
    result = rib.compute(_equal_paths(**bgp_multipath_props({"ibgp_v4": 4}, False)))

    assert len(_bgp_hops(result)) == 1


@pytest.mark.parametrize(
    ("line", "pairs"),
    [
        ("maximum-paths 4", [("ebgp", 4)]),
        ("maximum-paths ebgp 8", [("ebgp", 8)]),
        ("maximum-paths ibgp 2", [("ibgp", 2)]),
        ("maximum-paths ibgp unequal-cost 3", [("ibgp", 3)]),
        ("maximum-paths ibgp 4 unequal-cost", [("ibgp", 4)]),
        ("maximum-paths eibgp 6", [("ebgp", 6), ("ibgp", 6)]),
        ("maximum-paths mixed 2", [("ebgp", 2), ("ibgp", 2)]),
        ("maximum-prefix 100", []),
        ("maximum-paths 0", []),
    ],
)
def test_a_cisco_maximum_paths_line_names_its_session_types(line, pairs):
    assert parse_maximum_paths(line) == pairs


def test_the_ios_xe_parse_reads_maximum_paths_per_family_and_vrf():
    text = "\n".join(
        [
            "router bgp 65001",
            " bgp bestpath as-path multipath-relax",
            " address-family ipv4",
            "  maximum-paths 4",
            "  maximum-paths ibgp 2",
            " exit-address-family",
            " address-family ipv6",
            "  maximum-paths 3",
            " exit-address-family",
            " address-family ipv4 vrf RED",
            "  maximum-paths eibgp 6",
            " exit-address-family",
        ]
    )
    parsed = iosxe.parse_bgp_config(text)
    assert parsed is not None
    by_vrf = {p["vrf"]: p for p in parsed["processes"]}

    assert by_vrf["default"]["maximum_paths"] == {"ebgp_v4": 4, "ibgp_v4": 2, "ebgp_v6": 3}
    assert by_vrf["RED"]["maximum_paths"] == {"ebgp_v4": 6, "ibgp_v4": 6}
    assert all(p["multipath_relax"] for p in parsed["processes"])


def test_the_ios_xr_parse_reads_maximum_paths_in_the_process_and_a_vrf():
    text = "\n".join(
        [
            "router bgp 65001",
            " bgp bestpath as-path multipath-relax",
            " address-family ipv4 unicast",
            "  maximum-paths ebgp 4",
            "  maximum-paths ibgp 2",
            " !",
            " vrf RED",
            "  address-family ipv4 unicast",
            "   maximum-paths eibgp 8",
            "  !",
            " !",
        ]
    )
    parsed = iosxr_bgp.parse_bgp(text)
    assert parsed is not None
    by_vrf = {p["vrf"]: p for p in parsed["processes"]}

    assert by_vrf[""]["maximum_paths"] == {"ebgp_v4": 4, "ibgp_v4": 2}
    assert by_vrf[""]["multipath_relax"] is True
    assert by_vrf["RED"]["maximum_paths"] == {"ebgp_v4": 8, "ibgp_v4": 8}


def test_the_nx_os_parse_reads_maximum_paths_and_multipath_relax():
    text = "\n".join(
        [
            "router bgp 65001",
            "  bestpath as-path multipath-relax",
            "  address-family ipv4 unicast",
            "    maximum-paths 4",
            "    maximum-paths ibgp 2",
            "  vrf RED",
            "    address-family ipv6 unicast",
            "      maximum-paths 8",
        ]
    )
    by_vrf = {p["vrf"]: p for p in nxos.parse_bgp_config(text)}

    assert by_vrf[None]["maximum_paths"] == {"ebgp_v4": 4, "ibgp_v4": 2}
    assert by_vrf[None]["multipath_relax"] is True
    assert by_vrf["RED"]["maximum_paths"] == {"ebgp_v6": 8}
    assert "multipath_relax" not in by_vrf["RED"]


def test_the_vyos_routing_process_records_maximum_paths_and_multipath_relax():
    builder = GraphBuilder()
    vyos._bgp_stage(
        builder,
        {
            "system-as": "65000",
            "parameters": {"bestpath": {"as-path": {"multipath-relax": {}}}},
            "address-family": {
                "ipv4-unicast": {"maximum-paths": {"ebgp": "4", "ibgp": "2"}},
                "ipv6-unicast": {"maximum-paths": {"ebgp": "8"}},
            },
        },
        "device:1",
        "default",
        "vrf:device-1:default",
        "device:1",
        {},
        {},
    )
    (process,) = (n for n in builder.batch("vyos", "run").nodes if n.label == "RoutingProcess")

    assert process.props["multipath_config_recorded"] is True
    assert process.props["multipath_relax"] is True
    assert (
        process.props["maximum_paths_ebgp_v4"],
        process.props["maximum_paths_ibgp_v4"],
        process.props["maximum_paths_ebgp_v6"],
    ) == (4, 2, 8)


def test_the_routing_process_records_that_its_maximum_paths_were_read():
    assert bgp_multipath_props({}, False) == {"multipath_config_recorded": True, "multipath_relax": None}
    assert bgp_multipath_props({"ibgp_v6": 2, "ebgp_v4": 4}, True) == {
        "multipath_config_recorded": True,
        "multipath_relax": True,
        "maximum_paths_ebgp_v4": 4,
        "maximum_paths_ibgp_v6": 2,
    }
