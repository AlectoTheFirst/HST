"""BGP and OSPF configuration knobs the best-path, propagation and redistribution
engines read and that the collectors have to record: `always-compare-med`,
`next-hop-self`, `default-information originate` under OSPF and under BGP.

Each knob is recorded only when it is configured, so a node or a parsed process
without the key is the default behaviour."""

from __future__ import annotations

import copy

from tests.test_bgp_origin_routes import _BRANCH

from hst.collectors import iosxe, iosxr_bgp, nxos, vyos
from hst.collectors.cisco_common import _ospf_process, normalize_cisco, parse_ospf_redistribute_config
from hst.collectors.util import GraphBuilder
from hst.core import uid
from hst.core.identity import MemoryResolver
from hst.core.l3domain import DEFAULT_VRF

# --- always-compare-med ------------------------------------------------------------------


def test_iosxe_records_always_compare_med_for_every_process_of_the_router():
    parsed = iosxe.parse_bgp_config(
        """router bgp 65000
 bgp always-compare-med
 address-family ipv4
 exit-address-family
 address-family ipv4 vrf BLUE
 exit-address-family
"""
    )
    assert parsed is not None
    assert {p["vrf"]: p.get("always_compare_med") for p in parsed["processes"]} == {
        DEFAULT_VRF: True,
        "BLUE": True,
    }
    plain = iosxe.parse_bgp_config("router bgp 65000\n bgp router-id 192.0.2.1\n")
    assert plain is not None
    assert ["always_compare_med" in p for p in plain["processes"]] == [False]


def test_nxos_records_always_compare_med_in_the_scope_it_is_configured_in():
    processes = nxos.parse_bgp_config(
        """router bgp 65000
  bestpath always-compare-med
  vrf BLUE
    router-id 192.0.2.9
"""
    )
    assert {p["vrf"]: p.get("always_compare_med") for p in processes} == {None: True, "BLUE": None}


def test_iosxr_records_bestpath_med_always():
    parsed = iosxr_bgp.parse_bgp(
        """router bgp 65000
 bgp router-id 192.0.2.1
 bgp bestpath med always
!
"""
    )
    assert parsed is not None
    assert parsed["always_compare_med"] is True
    assert parsed["processes"][0]["always_compare_med"] is True
    off = iosxr_bgp.parse_bgp("router bgp 65000\n bgp router-id 192.0.2.1\n")
    assert off is not None
    assert "always_compare_med" not in off


def _vyos_bgp_nodes(bgp_cfg):
    builder = GraphBuilder()
    vyos._bgp_stage(builder, bgp_cfg, "device:1", "default", "vrf:device-1:default", "device:1", {}, {})
    return builder.batch("vyos", "run").nodes


def _vyos_process(params):
    nodes = _vyos_bgp_nodes({"system-as": "65000", "parameters": params})
    return next(node for node in nodes if node.label == "RoutingProcess")


def test_vyos_records_always_compare_med():
    assert _vyos_process({"always-compare-med": {}}).props["always_compare_med"] is True
    assert "always_compare_med" not in _vyos_process({}).props


# --- default-information originate under BGP ---------------------------------------------


def _bgp_process_props(bgp_text):
    inter = copy.deepcopy(_BRANCH)
    inter["routing"] = {"bgp": iosxe.parse_bgp_config(bgp_text)}
    batch = normalize_cisco(inter, source="iosxe", scope="iosxe:br1", l3dom="corp", resolver=MemoryResolver())
    (props,) = (n.props for n in batch.nodes if n.label == "RoutingProcess" and n.props.get("proto") == "bgp")
    return props


def test_iosxe_records_default_information_originate_per_address_family():
    parsed = iosxe.parse_bgp_config(
        """router bgp 65000
 address-family ipv4
  default-information originate
 exit-address-family
 address-family ipv6
 exit-address-family
 address-family ipv4 vrf BLUE
 exit-address-family
 address-family ipv6 vrf BLUE
  default-information originate
 exit-address-family
"""
    )
    assert parsed is not None
    afs = {p["vrf"]: p.get("default_information_originate_afs") for p in parsed["processes"]}
    assert afs == {DEFAULT_VRF: [4], "BLUE": [6]}


def test_iosxe_default_information_originate_reaches_the_process_node():
    on = _bgp_process_props(
        "router bgp 65001\n address-family ipv4\n  default-information originate\n exit-address-family\n"
    )
    assert on["default_information_originate_afs"] == [4]
    off = _bgp_process_props("router bgp 65001\n bgp router-id 10.255.0.1\n")
    assert "default_information_originate_afs" not in off


def test_nxos_records_default_information_originate_per_address_family():
    processes = nxos.parse_bgp_config(
        """router bgp 65000
  address-family ipv4 unicast
    default-information originate
  vrf BLUE
    address-family ipv6 unicast
      default-information originate
"""
    )
    afs = {p["vrf"]: p.get("default_information_originate_afs") for p in processes}
    assert afs == {None: [4], "BLUE": [6]}
    batch = nxos.bgp_stage(
        {"bgp": {"processes": processes}},
        dev="device:1",
        existing_vrf_uids=set(),
        source="nxos",
        scope="fixture",
    )
    props = {n.uid: n.props for n in batch.nodes if n.label == "RoutingProcess"}
    assert props[uid.routing_process("device:1", "BLUE", "bgp")]["default_information_originate_afs"] == [6]


def test_iosxr_records_default_information_originate_in_the_address_family():
    parsed = iosxr_bgp.parse_bgp(
        """router bgp 65000
 address-family ipv4 unicast
  default-information originate
 !
 vrf BLUE
  address-family ipv6 unicast
   default-information originate
  !
 !
!
"""
    )
    assert parsed is not None
    afs = {p["vrf"]: p.get("default_information_originate_afs") for p in parsed["processes"]}
    assert afs == {"": [4], "BLUE": [6]}


# --- next-hop-self -----------------------------------------------------------------------


def test_iosxe_records_next_hop_self_on_the_neighbor_and_through_its_peer_group():
    parsed = iosxe.parse_bgp_config(
        """router bgp 65000
 neighbor CORE peer-group
 neighbor CORE remote-as 65000
 neighbor 10.255.0.2 peer-group CORE
 neighbor 10.255.0.3 remote-as 65000
 neighbor 10.255.0.4 remote-as 65000
 address-family ipv4
  neighbor CORE next-hop-self
  neighbor 10.255.0.3 next-hop-self all
  neighbor 10.255.0.2 activate
  neighbor 10.255.0.3 activate
  neighbor 10.255.0.4 activate
 exit-address-family
"""
    )
    assert parsed is not None
    modes = {n["peer_ip"]: n.get("next_hop_self") for n in parsed["neighbors"]}
    assert modes == {"10.255.0.2": "ebgp", "10.255.0.3": "all", "10.255.0.4": None}


def test_next_hop_self_reaches_the_session_node_of_iosxe_and_nxos():
    inter = copy.deepcopy(_BRANCH)
    inter["routing"] = {
        "bgp": iosxe.parse_bgp_config(
            "router bgp 65001\n neighbor 10.255.0.2 remote-as 65001\n neighbor 10.255.0.2 next-hop-self all\n"
        )
    }
    batch = normalize_cisco(inter, source="iosxe", scope="iosxe:br1", l3dom="corp", resolver=MemoryResolver())
    (session,) = (n for n in batch.nodes if n.label == "BgpSession")
    assert session.props["next_hop_self"] == "all"

    processes = nxos.parse_bgp_config(
        """router bgp 65001
  neighbor 10.255.0.2
    remote-as 65001
    address-family ipv4 unicast
      next-hop-self
  neighbor 10.255.0.3
    remote-as 65001
    address-family ipv4 unicast
"""
    )
    batch = nxos.bgp_stage(
        {"bgp": {"processes": processes}},
        dev="device:1",
        existing_vrf_uids=set(),
        source="nxos",
        scope="fixture",
    )
    modes = {n.props["peer_ip"]: n.props.get("next_hop_self") for n in batch.nodes if n.label == "BgpSession"}
    assert modes == {"10.255.0.2": "ebgp", "10.255.0.3": None}


def test_nxos_next_hop_self_comes_through_a_peer_policy_template():
    processes = nxos.parse_bgp_config(
        """router bgp 65001
  template peer-policy CORE-POLICY
    next-hop-self all
  neighbor 10.255.0.2
    remote-as 65001
    address-family ipv4 unicast
      inherit peer-policy CORE-POLICY 10
"""
    )
    assert [n.get("next_hop_self") for n in processes[0]["neighbors"]] == ["all"]


def test_iosxr_next_hop_self_resolves_through_the_neighbor_group():
    parsed = iosxr_bgp.parse_bgp(
        """router bgp 65000
 neighbor-group CORE
  remote-as 65000
  address-family ipv4 unicast
   next-hop-self
  !
 !
 neighbor 10.255.0.2
  use neighbor-group CORE
 !
 neighbor 10.255.0.3
  remote-as 65000
 !
!
"""
    )
    assert parsed is not None
    sessions = {s["peer_ip"]: s.get("next_hop_self") for s in iosxr_bgp.resolve_bgp_sessions(parsed)}
    assert sessions == {"10.255.0.2": "ebgp", "10.255.0.3": None}


def test_vyos_records_nexthop_self_on_the_neighbor_and_through_its_peer_group():
    nodes = _vyos_bgp_nodes(
        {
            "system-as": "65000",
            "peer-group": {"CORE": {"address-family": {"ipv4-unicast": {"nexthop-self": {}}}}},
            "neighbor": {
                "10.255.0.2": {"remote-as": "65000", "peer-group": "CORE"},
                "10.255.0.3": {
                    "remote-as": "65000",
                    "address-family": {"ipv4-unicast": {"nexthop-self": {"force": {}}}},
                },
                "10.255.0.4": {"remote-as": "65000"},
            },
        }
    )
    modes = {n.props["peer_ip"]: n.props.get("next_hop_self") for n in nodes if n.label == "BgpSession"}
    assert modes == {"10.255.0.2": "ebgp", "10.255.0.3": "all", "10.255.0.4": None}


# --- default-information originate under OSPF --------------------------------------------


def test_the_cisco_ospf_parser_records_default_information_originate_and_always():
    config = parse_ospf_redistribute_config(
        """router ospf 1
 router-id 10.255.0.1
 default-information originate always metric 5
router ospf 2
 default-information originate
router ospf 3
 router-id 10.255.0.3
"""
    )
    assert config["1"]["default_information_originate"] is True
    assert config["1"]["default_information_originate_always"] is True
    assert config["2"]["default_information_originate"] is True
    assert "default_information_originate_always" not in config["2"]
    assert "default_information_originate" not in config["3"]


def test_the_nxos_ospf_parser_records_default_information_originate():
    entries = nxos.parse_ospf_config(
        """router ospf 1
  router-id 10.255.0.1
  default-information originate always route-map RM_DEFAULT
router ospf 2
  default-information originate
"""
    )
    assert entries[("1", "")]["default_information_originate_always"] is True
    assert entries[("2", "")]["default_information_originate"] is True
    assert "default_information_originate_always" not in entries[("2", "")]


def test_vyos_ospf_default_information_originate():
    always = {"protocols": {"ospf": {"default-information": {"originate": {"always": {}}}}}}
    assert vyos._ospf_default_originate(always, "") == {
        "default_information_originate": True,
        "default_information_originate_always": True,
    }
    plain = {"protocols": {"ospf": {"default-information": {"originate": {}}}}}
    assert vyos._ospf_default_originate(plain, "") == {"default_information_originate": True}
    assert vyos._ospf_default_originate({"protocols": {"ospf": {}}}, "") == {}


def test_the_ospf_process_node_records_default_information_originate_only_when_configured():
    builder = GraphBuilder()
    on = _ospf_process(
        builder,
        {"process": "1", "router_id": "10.255.0.1", "default_information_originate": True},
        dev="device:1",
        vname="default",
        inter={},
    )
    off = _ospf_process(
        builder, {"process": "2", "router_id": "10.255.0.2"}, dev="device:1", vname="blue", inter={}
    )
    assert builder.props("RoutingProcess", on)["default_information_originate"] is True
    assert "default_information_originate_always" not in builder.props("RoutingProcess", on)
    assert "default_information_originate" not in builder.props("RoutingProcess", off)
