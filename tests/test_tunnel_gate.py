"""Symbolic tunnel carrier and reciprocal decapsulation facts."""

from hst.path.addrsets import _intervals, _ports, _protoset
from hst.path.gates.tunnel import build_carrier_legs, carrier_legs
from hst.path.state import FlowRegion


def _inner():
    return FlowRegion.from_query(
        _intervals(["10.0.0.0/24"]),
        _intervals(["203.0.113.10"]),
        _protoset(["tcp"]),
        _ports("443"),
    )


def _inner_network():
    return FlowRegion.from_query(
        _intervals(["10.0.0.0/24"]),
        _intervals(["203.0.113.0/24"]),
        _protoset(["tcp"]),
        _ports("443"),
    )


def _row(**overrides):
    row = {
        "tunnel_uid": "tun:a",
        "tunnel_name": "office",
        "encap": "wireguard",
        "state": "up",
        "local_address": "192.0.2.1",
        "remote_address": "192.0.2.2",
        "carrier_proto": "udp",
        "carrier_port": 51820,
        "local_port": None,
        "allowed_ips": ["203.0.113.0/24"],
        "binding_kind": "endpoint",
        "local_interface_uid": "if:a:wg0",
        "local_device_uid": "dev:a",
        "local_context_uid": "vrf:a:overlay",
        "local_underlay_interface_uid": "if:a:eth0",
        "local_underlay_context_uid": "vrf:a:wan",
        "remote_interface_uid": "if:b:wg0",
        "remote_device_uid": "dev:b",
        "remote_context_uid": "vrf:b:overlay",
        "remote_underlay_interface_uid": "if:b:eth0",
        "remote_underlay_context_uid": "vrf:b:wan",
        "peer_tunnel_uid": "tun:b",
    }
    row.update(overrides)
    return row


def test_complete_reciprocal_tunnel_keeps_inner_and_outer_headers_separate():
    inner = _inner()
    (leg,) = build_carrier_legs([_row()], inner)

    assert leg.status == "complete" and leg.can_decapsulate
    assert leg.inner == inner
    assert leg.outer is not None and leg.outer != inner
    rect = leg.outer.rects[0]
    assert rect.proto == frozenset({17})
    assert rect.dport == tuple(_ports("51820"))
    assert (leg.remote_device_uid, leg.remote_context_uid, leg.peer_tunnel_uid) == (
        "dev:b",
        "vrf:b:overlay",
        "tun:b",
    )
    assert (leg.local_interface_uid, leg.local_underlay_context_uid) == (
        "if:a:wg0",
        "vrf:a:wan",
    )
    assert (leg.remote_interface_uid, leg.remote_underlay_context_uid) == (
        "if:b:wg0",
        "vrf:b:wan",
    )


def test_multiple_candidates_are_all_returned_and_none_is_selected():
    legs = build_carrier_legs([_row(), _row(tunnel_uid="tun:c", peer_tunnel_uid="tun:d")], _inner())
    assert [leg.tunnel_uid for leg in legs] == ["tun:a", "tun:c"]
    assert {leg.status for leg in legs} == {"ambiguous"}
    assert not any(leg.can_decapsulate for leg in legs)


def test_absent_carrier_endpoint_is_indeterminate():
    (leg,) = build_carrier_legs([_row(remote_address=None)], _inner())
    assert leg.status == "indeterminate"
    assert leg.outer is None
    assert "remote address" in leg.evidence[0]


def test_known_down_and_unobserved_state_stay_distinct():
    (down,) = build_carrier_legs([_row(state="down")], _inner())
    (unknown,) = build_carrier_legs([_row(state=None)], _inner())
    assert down.status == "down"
    assert unknown.status == "unknown"


def test_wireguard_uses_longest_allowed_ip_match_without_blanket_ambiguity():
    broad = _row(tunnel_uid="tun:broad", peer_tunnel_uid="peer:broad")
    narrow = _row(
        tunnel_uid="tun:narrow",
        peer_tunnel_uid="peer:narrow",
        allowed_ips=["203.0.113.10/32"],
    )
    (leg,) = build_carrier_legs([broad, narrow], _inner())
    assert leg.tunnel_uid == "tun:narrow"
    assert leg.status == "complete"


def test_wireguard_partitions_inner_region_between_disjoint_peers():
    left = _row(tunnel_uid="tun:left", peer_tunnel_uid="peer:left", allowed_ips=["203.0.113.0/25"])
    right = _row(tunnel_uid="tun:right", peer_tunnel_uid="peer:right", allowed_ips=["203.0.113.128/25"])

    legs = build_carrier_legs([left, right], _inner_network())

    assert [leg.tunnel_uid for leg in legs] == ["tun:left", "tun:right"]
    assert {leg.status for leg in legs} == {"complete"}
    destinations = [leg.inner.rects[0].dst for leg in legs]
    assert destinations == [tuple(_intervals(["203.0.113.0/25"])), tuple(_intervals(["203.0.113.128/25"]))]


def test_known_wireguard_peers_with_no_allowed_match_deny_the_inner_region():
    (leg,) = build_carrier_legs([_row(allowed_ips=["198.51.100.0/24"])], _inner())
    assert leg.status == "denied"
    assert leg.outer is None


def test_missing_wireguard_allowed_ips_makes_selection_unknown():
    (leg,) = build_carrier_legs([_row(allowed_ips=None)], _inner())
    assert leg.status == "unknown"


def test_portless_gre_and_ipsec_carriers_keep_port_unstated():
    for encap, proto in (("gre", "gre"), ("ipsec", "esp")):
        (leg,) = build_carrier_legs(
            [_row(encap=encap, carrier_proto=proto, carrier_port=None, allowed_ips=None)], _inner()
        )
        assert leg.status == "complete"
        assert leg.outer is not None and leg.outer.rects[0].dport is None


def test_gate_reads_all_candidates_through_the_path_session_seam(monkeypatch):
    seen = {}

    def read(session, query, **params):
        seen.update(params)
        assert "LIMIT 1" not in query
        assert "peer.local_address = remote_address" in query
        assert "remote_overlay:Interface" in query
        assert "local_underlay:Interface" in query
        return [_row()]

    monkeypatch.setattr("hst.path._read", read)
    legs = carrier_legs(object(), "if:a:wg0", _inner())
    assert seen == {"if_uid": "if:a:wg0"}
    assert legs[0].status == "complete"


def test_missing_remote_context_or_reciprocal_tunnel_never_invents_a_decap():
    (missing_context,) = build_carrier_legs([_row(remote_context_uid=None)], _inner())
    (missing_peer,) = build_carrier_legs([_row(peer_tunnel_uid=None, peer_remote_address=None)], _inner())
    assert missing_context.status == "indeterminate"
    assert missing_peer.status == "indeterminate"
    assert not missing_context.can_decapsulate and not missing_peer.can_decapsulate


def test_udp_requires_a_known_remote_port_and_source_port_stays_unstated():
    (missing,) = build_carrier_legs([_row(carrier_port=None)], _inner())
    (complete,) = build_carrier_legs([_row(local_port=None)], _inner())
    assert missing.status == "indeterminate" and missing.outer is None
    assert complete.outer is not None and complete.outer.rects[0].sport is None


def test_source_ip_match_alone_does_not_assert_encapsulation():
    (leg,) = build_carrier_legs([_row(binding_kind="source-selector")], _inner())
    assert leg.status == "indeterminate"
    assert "does not prove" in leg.evidence[0]


def test_the_nat_arm_starts_from_the_tunnels_own_far_node_and_is_pinned_to_the_run():
    from hst.path.gates import tunnel

    query = tunnel._CANDIDATES
    assert "CASE WHEN term_ip IS NOT NULL THEN nat_ip = term_ip ELSE nat_ip.ip = remote_address END" in query
    assert "nat_link.collection_ts = $snap" in query
    assert "direct_underlay.collection_ts = $snap" in query
