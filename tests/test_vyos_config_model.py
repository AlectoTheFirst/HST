"""VyOS configuration shapes: placeholder serials, the 1.3+ tunnel keys,
floating static forms and BGP peer-group inheritance."""

import json

from tests.test_vyos import BGP_CONFIG, VERSION, _batch, _connections, _device, _nh, _rib_batch, _route

from hst.collectors import vyos as vyos_mod
from hst.collectors.vyos import normalize_vyos
from hst.core import uid
from hst.core.identity import MemoryResolver, placeholder_serial
from hst.core.l3domain import DEFAULT_VRF

# --- a placeholder or an empty chassis serial names no chassis -------------------------


def test_the_placeholders_of_whitebox_and_virtual_boards_are_not_serials():
    for value in (
        "Not Specified",
        "System Serial Number",
        "0123456789",
        "XXXXXXXX",
        " not  specified ",
        "0000",
        "",
    ):
        assert placeholder_serial(value), value
    for value in ("QEMU1234", "VM-4c4c4544", "S1"):
        assert not placeholder_serial(value), value


def test_a_placeholder_serial_is_not_a_serial():
    """The registry keys a device by its serial first."""
    for placeholder in ("Not Specified", "System Serial Number", "0123456789", "XXXXXXXX"):
        registry = MemoryResolver()
        device = _device(_batch(version_text=f"Hardware S/N:     {placeholder}\n", resolver=registry))
        assert device.props.get("serial") is None, placeholder
        assert device.uid == registry.resolve_device("ref", "vyos:gw", None)


def test_an_empty_serial_is_not_read_off_the_next_line():
    """vyos-1x prints an empty S/N when the DMI file is empty."""
    for text in (
        "Version:          VyOS 1.4.0\nHardware S/N:     \nHardware UUID:    4c4c4544\n",
        "Version:          VyOS 1.4.0\nHardware S/N:\nHardware UUID:\n",
        "Version:          VyOS 1.4.0\r\nHardware S/N:     \r\nHardware UUID:    4c4c4544\r\n",
    ):
        assert _device(_batch(version_text=text)).props.get("serial") is None, text


def test_two_routers_with_one_placeholder_serial_stay_two_devices():
    registry = MemoryResolver()
    for text in ("Hardware S/N:     Not Specified\n", "Hardware S/N:\nHardware UUID:\n"):
        one = _batch(version_text=text, source_name="edge-a", resolver=registry)
        two = _batch(version_text=text, source_name="edge-b", resolver=registry)
        assert _device(one).uid != _device(two).uid, text


def test_a_real_serial_is_read():
    text = "Version:          VyOS 1.4.0\nHardware S/N:     VM-4c4c4544 \nHardware UUID:    4c4c\n"
    assert _device(_batch(version_text=text)).props["serial"] == "VM-4c4c4544"


# --- tunnels read the VyOS 1.3+ endpoint keys -------------------------------------------


def _tunnel_router(tunnels: dict):
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {"ethernet": {"eth0": {"address": ["203.0.113.1/24"]}}, "tunnel": tunnels},
    }
    return normalize_vyos({"config": cfg, "version_text": VERSION, "links": []}, l3dom="dc1")


def _tunnels(batch) -> dict[str, dict]:
    return {n.uid: n.props for n in batch.nodes if n.label == "Tunnel"}


def test_gre_tunnels_with_the_current_keys_are_one_tunnel_each():
    """VyOS 1.3+ writes the far end as `remote` (migration interfaces 19-to-20)."""
    batch = _tunnel_router(
        {
            "tun0": {"encapsulation": "gre", "source-address": "203.0.113.1", "remote": "198.51.100.10"},
            "tun1": {"encapsulation": "gre", "source-address": "203.0.113.1", "remote": "198.51.100.20"},
        }
    )
    tunnels = _tunnels(batch)
    first = uid.tunnel("gre", "203.0.113.1", "198.51.100.10")
    second = uid.tunnel("gre", "203.0.113.1", "198.51.100.20")
    assert set(tunnels) == {first, second}
    assert {p["endpoint"] for p in tunnels.values()} == {"198.51.100.10", "198.51.100.20"}
    assert {p["local_address_source"] for p in tunnels.values()} == {"configured"}
    ends = {
        (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENDPOINT" and r.start_uid in tunnels
    }
    assert ends == {(first, uid.interface("dev:gw", "tun0")), (second, uid.interface("dev:gw", "tun1"))}
    assert set(_connections(batch)) == {
        uid.overlay_connection("gre", "203.0.113.1", "198.51.100.10"),
        uid.overlay_connection("gre", "203.0.113.1", "198.51.100.20"),
    }


def test_a_tunnel_bound_to_a_source_interface_sends_from_its_address():
    batch = _tunnel_router(
        {"tun0": {"encapsulation": "gre", "source-interface": "eth0", "remote": "198.51.100.10"}}
    )
    tunnels = _tunnels(batch)
    assert list(tunnels) == [uid.tunnel("gre", "203.0.113.1", "198.51.100.10")]
    [props] = tunnels.values()
    assert props["local_address"] == "203.0.113.1"
    assert props["local_address_source"] == "derived:source-interface"


def test_tunnels_missing_an_end_are_not_one_node():
    batch = _tunnel_router(
        {
            "tun0": {"encapsulation": "gre", "source-address": "203.0.113.1"},
            "tun1": {"encapsulation": "gre", "source-address": "203.0.113.1"},
        }
    )
    tunnels = _tunnels(batch)
    assert len(tunnels) == 2
    ends = {
        (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENDPOINT" and r.start_uid in tunnels
    }
    assert {end for _tu, end in ends} == {uid.interface("dev:gw", "tun0"), uid.interface("dev:gw", "tun1")}
    assert len({tu for tu, _end in ends}) == 2


def test_two_gre_tunnels_between_one_pair_of_addresses_are_told_apart_by_their_key():
    def keyed(key: str) -> dict:
        return {
            "encapsulation": "gre",
            "source-address": "203.0.113.1",
            "remote": "198.51.100.10",
            "parameters": {"ip": {"key": key}},
        }

    batch = _tunnel_router({"tun0": keyed("1"), "tun1": keyed("2")})
    pair = uid.tunnel("gre", "203.0.113.1", "198.51.100.10")
    assert set(_tunnels(batch)) == {f"{pair}~key1", f"{pair}~key2"}
    assert len(_connections(batch)) == 2


# --- a floating static form is not the route ---------------------------------------------


def _static_patch(route: dict, prefix: str = "10.20.0.0/16"):
    def patch(cfg):
        cfg["interfaces"]["vti"] = {"vti0": {"address": ["10.255.0.1/30"]}}
        cfg["protocols"]["static"]["route"][prefix] = route

    return patch


def _statics_of(batch, prefix: str = "10.20.0.0/16") -> list:
    return [r for r in batch.rels if r.rel_type == "STATIC_ROUTE" and r.end_uid.endswith(f":{prefix}")]


def _learned_of(batch, prefix: str = "10.20.0.0/16") -> list:
    return [r for r in batch.rels if r.rel_type == "LEARNED_ROUTE" and r.end_uid.endswith(f":{prefix}")]


FLOATING = {"interface": {"vti0": {}}, "blackhole": {"distance": "255"}}


def test_a_floating_discard_beside_an_interface_is_not_the_route():
    """The route-based VPN shape is `interface vti0` plus `blackhole distance 255`."""
    batch = _rib_batch(routes=_route("10.20.0.0/16", _nh(dev="vti0")), cfg_patch=_static_patch(FLOATING))
    [static] = _statics_of(batch)
    assert static.props.get("discard") is None
    assert static.props["interface"] == "vti0" and static.props["distance"] == 1
    assert static.props.get("rib_confirmed") is True
    assert not _learned_of(batch)
    via = {r.end_uid for r in batch.rels if r.rel_type == "VIA" and r.start_uid == static.end_uid}
    assert via == {"dev:gw/if/vti0"}


def test_a_floating_discard_the_router_installed_comes_from_the_rib():
    """With the tunnel down zebra installs the discard: the RIB row says so, and
    it is not taken for the config's interface form."""
    batch = _rib_batch(routes=_route("10.20.0.0/16", _nh()), cfg_patch=_static_patch(FLOATING))
    assert [r.props.get("interface") for r in _statics_of(batch)] == ["vti0"]
    # the installed row is a drop, written as the static path writes one
    assert [
        (r.props.get("next_hop"), r.props.get("interface"), r.props.get("discard"))
        for r in _learned_of(batch)
    ] == [(None, None, "blackhole")]


def test_a_floating_discard_in_frr_flag_form_is_a_discard_row():
    """FRR prints a blackhole-type nexthop as `unreachable` plus its kind."""
    nh = _nh(unreachable=True, blackhole=True)
    batch = _rib_batch(routes=_route("10.20.0.0/16", nh), cfg_patch=_static_patch(FLOATING))
    assert [r.props.get("discard") for r in _learned_of(batch)] == ["blackhole"]


def test_a_bgp_blackhole_row_no_static_declares_is_a_discard():
    batch = _rib_batch(routes=_route("10.20.0.0/16", _nh(unreachable=True, blackhole=True), protocol="bgp"))
    [learned] = _learned_of(batch)
    assert learned.props.get("discard") == "blackhole"
    assert learned.props.get("protocol") == "bgp"


def test_reject_and_prohibit_rib_rows_keep_their_kind():
    reject = _rib_batch(routes=_route("10.20.0.0/16", _nh(unreachable=True, reject=True)))
    assert [r.props.get("discard") for r in _learned_of(reject)] == ["reject"]
    prohibit = _rib_batch(
        routes=_route("10.20.0.0/16", _nh(**{"unreachable": True, "admin-prohibited": True}))
    )
    assert [r.props.get("discard") for r in _learned_of(prohibit)] == ["prohibit"]


def test_a_forwarding_rib_row_carries_no_discard():
    batch = _rib_batch(routes=_route("10.20.0.0/16", _nh(ip="192.168.1.9", dev="eth0"), protocol="bgp"))
    [learned] = _learned_of(batch)
    assert learned.props.get("discard") is None and learned.props["next_hop"] == "192.168.1.9"


def test_a_discard_of_the_lower_distance_is_the_route():
    batch = _rib_batch(cfg_patch=_static_patch({"interface": {"vti0": {"distance": "10"}}, "reject": {}}))
    assert [(r.props.get("discard"), r.props.get("distance")) for r in _statics_of(batch)] == [("reject", 1)]


def test_a_disabled_next_hop_is_not_a_route():
    route = {"next-hop": {"192.168.1.9": {"disable": {}}, "192.168.1.10": {"distance": "5"}}}
    batch = _rib_batch(cfg_patch=_static_patch(route))
    assert [(r.props.get("next_hop"), r.props.get("distance")) for r in _statics_of(batch)] == [
        ("192.168.1.10", 5)
    ]


# --- BGP neighbors inherit from their peer-group -----------------------------------------


def _peer_group_config() -> dict:
    cfg = json.loads(json.dumps(BGP_CONFIG))
    bgp = cfg["protocols"]["bgp"]
    bgp["peer-group"] = {
        "SPINES": {
            "remote-as": "65100",
            "address-family": {
                "ipv4-unicast": {
                    "prefix-list": {"import": "CUSTOMER-IN"},
                    "route-map": {"export": "CUSTOMER-OUT"},
                }
            },
        }
    }
    bgp["neighbor"]["10.1.0.1"] = {"peer-group": "SPINES"}
    # a member's own address-family setting leaves the group's policies in force
    bgp["neighbor"]["10.1.0.2"] = {
        "peer-group": "SPINES",
        "address-family": {"ipv4-unicast": {"soft-reconfiguration": {"inbound": {}}}},
    }
    bgp["neighbor"]["10.1.0.3"] = {"remote-as": "internal"}
    return cfg


def _peer_group_batch():
    return normalize_vyos({"config": _peer_group_config(), "version_text": VERSION, "links": []}, l3dom="wan")


def test_a_peer_group_member_takes_the_group_remote_as_and_policies():
    batch = _peer_group_batch()
    sessions = {n.props["peer_ip"]: (n.uid, n.props) for n in batch.nodes if n.label == "BgpSession"}
    for peer in ("10.1.0.1", "10.1.0.2"):
        su, props = sessions[peer]
        assert props["peer_asn"] == 65100 and props["peer_group"] == "SPINES"
        assert props["afi_safi"] == ["ipv4-unicast"]
        assert (props["import_policy_name"], props["import_policy_kind"]) == ("CUSTOMER-IN", "prefix-list")
        assert (props["export_policy_name"], props["export_policy_kind"]) == ("CUSTOMER-OUT", "route-map")
        filtered = {
            r.props["direction"] for r in batch.rels if r.rel_type == "FILTERED_BY" and r.start_uid == su
        }
        assert filtered == {"in", "out"}


def test_remote_as_internal_is_the_process_asn():
    sessions = {n.props["peer_ip"]: n.props for n in _peer_group_batch().nodes if n.label == "BgpSession"}
    assert sessions["10.1.0.3"]["peer_asn"] == sessions["10.1.0.3"]["local_asn"] == 65000
    # `auto` names no ASN
    assert "192.0.2.9" not in sessions


def test_bgp_capture_targets_include_the_peer_group_members():
    targets = set(vyos_mod.bgp_capture_targets(_peer_group_config()))
    assert {(DEFAULT_VRF, "10.1.0.1"), (DEFAULT_VRF, "10.1.0.2"), (DEFAULT_VRF, "10.1.0.3")} <= targets
    assert (DEFAULT_VRF, "192.0.2.9") not in targets
