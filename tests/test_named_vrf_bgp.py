from hst.collectors import iosxe, iosxr, iosxr_bgp
from hst.core import uid
from hst.core.l3domain import DEFAULT_VRF


def test_iosxe_bgp_config_keeps_named_vrf_process_identity():
    parsed = iosxe.parse_bgp_config(
        """router bgp 65000
 bgp router-id 192.0.2.1
 neighbor 192.0.2.2 remote-as 65001
 address-family ipv4
  neighbor 192.0.2.2 activate
 exit-address-family
 address-family ipv4 vrf BLUE
  neighbor 198.51.100.2 remote-as 65100
  neighbor 198.51.100.2 route-map BLUE-IN in
 exit-address-family
"""
    )

    assert parsed is not None
    processes = {p["vrf"]: p for p in parsed["processes"]}
    assert processes[DEFAULT_VRF]["neighbors"][0]["peer_ip"] == "192.0.2.2"
    assert processes["BLUE"]["af"] == 4
    assert processes["BLUE"]["neighbors"] == [
        {
            "peer_ip": "198.51.100.2",
            "remote_as": 65100,
            "route_map_in": "BLUE-IN",
        }
    ]


def test_iosxe_named_af_inherits_global_neighbor_transport_fields():
    parsed = iosxe.parse_bgp_config(
        """router bgp 65000
 neighbor 198.51.100.2 remote-as 65100
 neighbor 198.51.100.2 description blue-peer
 address-family ipv4 vrf BLUE
  neighbor 198.51.100.2 activate
 exit-address-family
"""
    )

    assert parsed is not None
    blue = next(p for p in parsed["processes"] if p["vrf"] == "BLUE")
    assert blue["neighbors"] == [
        {
            "peer_ip": "198.51.100.2",
            "remote_as": 65100,
            "description": "blue-peer",
        }
    ]


def test_iosxe_named_vrf_observation_uses_scoped_command_and_uids():
    config = iosxe.parse_bgp_config(
        """router bgp 65000
 address-family ipv4 vrf BLUE
  neighbor 198.51.100.2 remote-as 65100
 exit-address-family
"""
    )
    command = iosxe.bgp_route_command("198.51.100.2", "accepted", "BLUE")
    table = (
        "     Network          Next Hop            Metric LocPrf Weight Path\n"
        " *>  10.0.0.0/24      198.51.100.2             0    100      0 65100 i\n"
    )
    observed = iosxe.parse_bgp_observations({command: table}, config)
    rows = iosxe.bgp_side_rows({"bgp_observed": observed}, "device:1")
    route = rows["bgp_session_routes"][0]
    assert command == "show ip bgp vpnv4 vrf BLUE neighbors 198.51.100.2 routes"
    assert route["context_uid"] == uid.vrf("device:1", "BLUE")
    assert route["session_uid"] == uid.bgp_session(
        uid.routing_process("device:1", "BLUE", "bgp"), "198.51.100.2", "BLUE"
    )


def test_iosxr_named_vrf_config_and_observation_keep_process_identity():
    text = """router bgp 65000
 bgp router-id 192.0.2.1
 vrf BLUE
  neighbor 198.51.100.2
   remote-as 65100
   address-family ipv4 unicast
    route-policy BLUE-IN in
!"""
    config = iosxr_bgp.parse_bgp(text)
    assert config is not None
    blue = next(p for p in config["processes"] if p["vrf"] == "BLUE")
    assert iosxr_bgp.resolve_bgp_sessions(blue)[0]["peer_asn"] == 65100

    command = iosxr.bgp_route_command("198.51.100.2", "advertised", "BLUE")
    table = (
        "   Network            Next Hop            Metric LocPrf Weight Path\n"
        "*> 10.0.0.0/24        198.51.100.2             0    100      0 65100 i\n"
    )
    observed = iosxr.parse_bgp_observations({command: table}, config)
    rows = iosxr.bgp_side_rows({"bgp_observed": observed}, "device:1")
    route = rows["bgp_session_routes"][0]
    assert command == "show bgp vrf BLUE ipv4 unicast neighbors 198.51.100.2 advertised-routes"
    assert route["context_uid"] == uid.vrf("device:1", "BLUE")
    assert route["session_uid"] == uid.bgp_session(
        uid.routing_process("device:1", "BLUE", "bgp"), "198.51.100.2", "BLUE"
    )
