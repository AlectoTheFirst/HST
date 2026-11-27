"""The integrated routing calculation: one main RIB per forwarding
context from connected, static, OSPF and BGP inputs, selection by
administrative distance, recursive next-hop resolution, redistribution,
leaking, the compiled FIB, and validation against observed rib rows."""

import copy
import ipaddress
import random

import pytest
from tests.support.cputime import cpu_time

from hst import path as pathmod
from hst.path.gates.routing import _route_partition
from hst.simul import platforms, rib
from hst.simul.errors import ErrorSink
from hst.simul.propagate import SimulationInput

AREA_0 = "0.0.0.0"  # noqa: S104 - an OSPF area id, not a bind address
R1, R2, R3 = "10.255.0.1", "10.255.0.2", "10.255.0.3"
MASK_24, MASK_30, MASK_32 = "255.255.255.0", "255.255.255.252", "255.255.255.255"
CTX = "vrf:r1:default"
DEV = "dev:r1"


# --- fixture helpers ------------------------------------------------------------------


def _ctx(uid=CTX, device_uid=DEV, platform="nxos", name="default"):
    return {"uid": uid, "device_uid": device_uid, "name": name, "platform": platform}


def _connected(prefix, interface, context_uid=CTX):
    return {"context_uid": context_uid, "prefix": prefix, "interface": interface}


def _static(prefix, next_hop=None, interface=None, context_uid=CTX, **over):
    return {
        "context_uid": context_uid,
        "prefix": prefix,
        "next_hop": next_hop,
        "interface": interface,
        "next_hop_context_uid": None,
        "discard": None,
        **over,
    }


def _process(uid, context_uid, asn, router_id, platform="nxos", **extra):
    return {
        "uid": uid,
        "context_uid": context_uid,
        "proto": "bgp",
        "asn": asn,
        "router_id": router_id,
        "platform": platform,
        **extra,
    }


def _session(uid, process_uid, local_asn, peer_asn, local_ip, peer_ip, **kwargs):
    return {
        "uid": uid,
        "process_uid": process_uid,
        "local_asn": local_asn,
        "peer_asn": peer_asn,
        "local_ip": local_ip,
        "peer_ip": peer_ip,
        **kwargs,
    }


def _path(session_uid, prefix, next_hop, *, direction="received", as_path="", local_pref=100, med=None):
    return {
        "device_uid": DEV,
        "context_uid": CTX,
        "session_uid": session_uid,
        "peer_ip": next_hop,
        "af": 4,
        "safi": "unicast",
        "direction": direction,
        "rib_type": "adj-rib-in" if direction == "received" else "loc-rib",
        "policy_stage": "pre-import" if direction == "received" else "post-import",
        "path_id": None,
        "prefix": prefix,
        "prefixlen": ipaddress.ip_network(prefix).prefixlen,
        "next_hop": next_hop,
        "next_hop_context_uid": None,
        "as_path": as_path,
        "local_pref": local_pref,
        "med": med,
        "origin": "igp",
        "communities": None,
        "best": None,
    }


def _rib(
    prefix, next_hop, protocol, metric=0, interface="Ethernet1/1", next_hop_context_uid=None, discard=None
):
    return {
        "prefix": prefix,
        "next_hop": next_hop,
        "next_hop_context_uid": next_hop_context_uid,
        "interface": interface,
        "protocol": protocol,
        "discard": discard,
        "metric": metric,
        "prefixlen": ipaddress.ip_network(prefix).prefixlen,
        "af": 4,
    }


def _lsa(lsa_type, lsid, adv_router, area=AREA_0, **over):
    row = {
        "process": "1",
        "area": area,
        "lsa_type": lsa_type,
        "lsid": lsid,
        "adv_router": adv_router,
        "seq": 0x80000001,
        "age": 100,
        "metric": None,
        "links": None,
        "attached_routers": None,
        "mask": None,
        "forwarding_address": None,
        "metric_type": None,
    }
    row.update(over)
    return row


def _link(link_type, link_id, link_data, metric):
    return {"link_type": link_type, "link_id": link_id, "link_data": link_data, "metric": metric}


def _lsdb():
    return [
        _lsa(
            "router",
            R1,
            R1,
            links=[
                _link("point-to-point", R2, "10.0.12.1", 10),
                _link("stub", "10.0.12.0", MASK_30, 10),
                _link("point-to-point", R3, "10.0.13.1", 20),
                _link("stub", "10.0.13.0", MASK_30, 20),
                _link("stub", R1, MASK_32, 1),
            ],
        ),
        _lsa(
            "router",
            R2,
            R2,
            links=[
                _link("point-to-point", R1, "10.0.12.2", 10),
                _link("stub", "10.0.12.0", MASK_30, 10),
                _link("stub", R2, MASK_32, 1),
                _link("stub", "192.168.2.0", MASK_24, 5),
            ],
        ),
        _lsa(
            "router",
            R3,
            R3,
            links=[
                _link("point-to-point", R1, "10.0.13.3", 20),
                _link("stub", "10.0.13.0", MASK_30, 20),
                _link("stub", R3, MASK_32, 1),
            ],
        ),
    ]


def _ospf_entry(context_uid=CTX, router_id=R1, uid="rp:r1:ospf", rows=None, **extra):
    return {
        "uid": uid,
        "context_uid": context_uid,
        "router_id": router_id,
        "process": "1",
        "rows": _lsdb() if rows is None else rows,
        "area_types": {},
        "coverage": "complete",
        **extra,
    }


def _r1_connected():
    return [
        _connected("10.0.12.0/30", "Ethernet1/1"),
        _connected("10.0.13.0/30", "Ethernet1/2"),
        _connected("10.255.0.1/32", "loopback0"),
    ]


def _rows(result, context_uid=CTX):
    """(prefix, protocol, next_hop) of every installed row of one context."""
    return [
        (r["prefix"], r["protocol"], r["next_hop"]) for r in result.rib if r["context_uid"] == context_uid
    ]


def _row(result, prefix, context_uid=CTX):
    rows = [r for r in result.rib if r["context_uid"] == context_uid and r["prefix"] == prefix]
    assert len(rows) == 1, rows
    return rows[0]


# --- two peers, one prefix ---------------------------------------------------------------
#
# R1 (AS 65001) peers with P1 (AS 65002) over 10.0.1.0/30 and with P2
# (AS 65003) over 10.0.2.0/30. Both advertise 203.0.113.0/24. R1's inbound
# route-map on the P1 session sets local preference 200.

P1_SESSION, P2_SESSION = "bgp:r1:p1", "bgp:r1:p2"

LP_200 = {
    "name": "RM_P1_IN",
    "kind": "route-map",
    "entries": [{"seq": 10, "kind": "clause", "action": "permit", "set_local_pref": 200}],
}


def _two_peer_input(observed=True):
    sessions = [
        _session(
            P1_SESSION,
            "rp:r1:bgp",
            65001,
            65002,
            "10.0.1.1",
            "10.0.1.2",
            import_policy_name="RM_P1_IN",
            import_policy_kind="route-map",
        ),
        _session(P2_SESSION, "rp:r1:bgp", 65001, 65003, "10.0.2.1", "10.0.2.2"),
    ]
    processes = [_process("rp:r1:bgp", CTX, 65001, R1)]
    paths = [
        _path(P1_SESSION, "203.0.113.0/24", "10.0.1.2", as_path="65002"),
        _path(P2_SESSION, "203.0.113.0/24", "10.0.2.2", as_path="65003"),
    ]
    status = {
        (P1_SESSION, "received"): "complete" if observed else "not-captured",
        (P2_SESSION, "received"): "complete" if observed else "not-captured",
        (P1_SESSION, "accepted"): "not-captured",
        (P2_SESSION, "accepted"): "not-captured",
    }
    return rib.RibInput(
        contexts=[_ctx()],
        connected=[_connected("10.0.1.0/30", "Ethernet1/1"), _connected("10.0.2.0/30", "Ethernet1/2")],
        bgp=SimulationInput(processes=processes, sessions=sessions, policies=[LP_200]),
        observed_paths=paths if observed else [],
        direction_status=status,
        platform="nxos",
    )


def test_two_peers_one_prefix_local_preference_picks_the_policy_winner():
    result = rib.compute(_two_peer_input())
    row = _row(result, "203.0.113.0/24")
    assert row["protocol"] == "bgp"
    assert row["next_hop"] == "10.0.1.2"
    assert row["local_pref"] == 200
    assert row["as_path"] == [65002]
    assert row["admin"] == 20
    assert row["igp_cost"] == 0, "the next hop is on a connected prefix"
    assert row["learned_from_session"] == P1_SESSION
    assert [g["kind"] for g in result.gaps] == []
    assert result.model_errors == []


def test_withdrawing_the_winner_selects_the_other_and_resolves_its_next_hop():
    """`bgp_session.shut` on the winning peering: the P2 path is the selection
    and its next hop resolves through the remaining RIB (R1's connected
    10.0.2.0/30), with nothing inferred about what P1 would have sent."""
    before = _two_peer_input()
    after = rib.apply_intents(before, [{"kind": "bgp_session.shut", "params": {"session": P1_SESSION}}])
    result = rib.compute(after)
    row = _row(result, "203.0.113.0/24")
    assert row["next_hop"] == "10.0.2.2"
    assert row["local_pref"] == 100
    assert row["learned_from_session"] == P2_SESSION
    assert result.model_errors == []
    # the input handed in was not written to
    assert _row(rib.compute(before), "203.0.113.0/24")["next_hop"] == "10.0.1.2"


def test_an_unresolvable_next_hop_is_not_installed_and_is_a_named_gap():
    inp = _two_peer_input()
    inp.static = [_static("172.16.0.0/16", "10.99.0.2")]
    inp.observed_paths.append(_path(P2_SESSION, "198.51.100.0/24", "10.77.0.1", as_path="65003"))
    result = rib.compute(inp)
    prefixes = [r["prefix"] for r in result.rib]
    assert "172.16.0.0/16" not in prefixes
    assert "198.51.100.0/24" not in prefixes
    gaps = {(g["kind"], g["prefix"], g["protocol"], g["next_hop"]) for g in result.gaps}
    assert gaps == {
        ("unresolved-next-hop", "172.16.0.0/16", "static", "10.99.0.2"),
        ("unresolved-next-hop", "198.51.100.0/24", "bgp", "10.77.0.1"),
    }
    assert result.model_errors == []


# --- administrative distance ----------------------------------------------------------


def test_a_static_beats_an_ospf_route_on_administrative_distance_and_loses_to_a_connected_one():
    inp = rib.RibInput(
        contexts=[_ctx()],
        connected=[*_r1_connected(), _connected("10.255.0.3/32", "tunnel0")],
        static=[_static("192.168.2.0/24", "10.0.13.3")],
        ospf=[_ospf_entry()],
    )
    result = rib.compute(inp)
    assert _rows(result) == [
        ("10.0.12.0/30", "connected", None),
        ("10.0.13.0/30", "connected", None),
        ("10.255.0.1/32", "connected", None),
        ("10.255.0.2/32", "ospf", "10.0.12.2"),
        ("10.255.0.3/32", "connected", None),
        ("192.168.2.0/24", "static", "10.0.13.3"),
    ]
    assert _row(result, "192.168.2.0/24")["admin"] == 1
    assert _row(result, "10.255.0.2/32")["admin"] == 110
    assert _row(result, "10.255.0.2/32")["metric"] == 11
    assert result.model_errors == []


def test_a_platform_with_no_profile_is_not_reported_for_connected_and_static_routes():
    inp = rib.RibInput(
        contexts=[_ctx(platform="netscaler")],
        connected=_r1_connected(),
        static=[_static("192.168.2.0/24", "10.0.13.3")],
    )
    result = rib.compute(inp)
    assert (_row(result, "10.0.13.0/30")["admin"], _row(result, "192.168.2.0/24")["admin"]) == (0, 1)
    assert result.model_errors == []


def test_a_platform_with_no_profile_is_reported_for_an_ospf_process():
    inp = rib.RibInput(
        contexts=[_ctx(platform="netscaler")],
        connected=_r1_connected(),
        ospf=[_ospf_entry()],
    )
    assert "unknown-platform" in {error["kind"] for error in rib.compute(inp).model_errors}


@pytest.mark.parametrize(
    "platform", [platforms.IOSXE, platforms.NXOS, platforms.IOSXR, platforms.FRR_TRADITIONAL]
)
def test_administrative_distances_per_platform(platform):
    assert [
        platforms.admin_distance(platform, p) for p in ("connected", "static", "ebgp", "ospf", "ibgp")
    ] == [
        0,
        1,
        20,
        110,
        200,
    ]


# --- OSPF cost and the igp_cost tie-break ----------------------------------------------
#
# R1 has two iBGP peers, R2 and R3, each supplying 203.0.113.0/24 with the same
# attributes and its own loopback as the next hop. OSPF costs the loopbacks at
# 11 (R2) and 21 (R3), so the R2 path wins on IGP cost until R1's interface
# toward R2 is re-costed.

R2_SESSION, R3_SESSION = "bgp:r1:r2", "bgp:r1:r3"


def _ibgp_input():
    sessions = [
        # a collector states the setting on every session; two iBGP sessions
        # without it make R1's reflection unknown
        _session(R2_SESSION, "rp:r1:bgp", 65001, 65001, R1, R2, route_reflector_client=False),
        _session(R3_SESSION, "rp:r1:bgp", 65001, 65001, R1, R3, route_reflector_client=False),
    ]
    return rib.RibInput(
        contexts=[_ctx()],
        connected=_r1_connected(),
        ospf=[_ospf_entry()],
        bgp=SimulationInput(processes=[_process("rp:r1:bgp", CTX, 65001, R1)], sessions=sessions),
        observed_paths=[
            _path(R2_SESSION, "203.0.113.0/24", R2),
            _path(R3_SESSION, "203.0.113.0/24", R3),
        ],
        direction_status={(R2_SESSION, "received"): "complete", (R3_SESSION, "received"): "complete"},
    )


def test_an_ospf_cost_change_moves_a_bgp_next_hops_resolution_and_the_igp_cost_tie_break():
    before = rib.compute(_ibgp_input())
    row = _row(before, "203.0.113.0/24")
    assert (row["next_hop"], row["igp_cost"], row["session_protocol"], row["admin"]) == (R2, 11, "ibgp", 200)

    errors = ErrorSink()
    changed = rib.apply_intents(
        _ibgp_input(),
        [{"kind": "ospf.interface_cost", "params": {"router_id": R1, "address": "10.0.12.1", "cost": 50}}],
        errors,
    )
    after = rib.compute(changed)
    row = _row(after, "203.0.113.0/24")
    assert (row["next_hop"], row["igp_cost"]) == (R3, 21)
    assert _row(after, "10.255.0.2/32")["metric"] == 51
    assert errors.as_dicts() == []
    assert after.model_errors == []


def test_an_ospf_adjacency_loss_removes_the_next_hops_route_and_the_path_with_it():
    changed = rib.apply_intents(
        _ibgp_input(), [{"kind": "ospf.adjacency_down", "params": {"router_a": R1, "router_b": R2}}]
    )
    after = rib.compute(changed)
    assert _row(after, "203.0.113.0/24")["next_hop"] == R3
    assert "10.255.0.2/32" not in [r["prefix"] for r in after.rib]
    unresolved = [g for g in after.gaps if g["kind"] == "unresolved-next-hop"]
    assert [(g["prefix"], g["next_hop"]) for g in unresolved] == [("203.0.113.0/24", R2)]


def test_a_routing_intent_outside_the_catalog_is_refused_by_name():
    with pytest.raises(ValueError, match="not a routing intent"):
        rib.apply_intents(_ibgp_input(), [{"kind": "fw_rule.add", "params": {}}])


def test_an_intent_that_changes_nothing_is_reported():
    errors = ErrorSink()
    rib.apply_intents(
        _ibgp_input(),
        [{"kind": "ospf.interface_cost", "params": {"router_id": R1, "address": "10.9.9.9", "cost": 5}}],
        errors,
    )
    rib.apply_intents(
        _ibgp_input(), [{"kind": "bgp_session.shut", "params": {"session": "bgp:nowhere"}}], errors
    )
    assert [e["kind"] for e in errors.as_dicts()] == ["ospf-change-no-effect", "unknown-bgp-session"]


# --- redistribution ----------------------------------------------------------------------

RM_STATIC = {
    "name": "RM_STATIC",
    "kind": "route-map",
    "entries": [
        {
            "seq": 10,
            "kind": "clause",
            "action": "permit",
            "set_local_pref": 300,
            "set_communities": ["65001:100"],
        }
    ],
}


def _redistribution_input(route_map="RM_STATIC"):
    """R1 (AS 65001) peers with P1 (AS 65002, in the input) and redistributes
    its static route through RM_STATIC."""
    p1_ctx = "vrf:p1:default"
    return rib.RibInput(
        contexts=[_ctx(), _ctx(uid=p1_ctx, device_uid="dev:p1")],
        connected=[
            _connected("10.0.1.0/30", "Ethernet1/1"),
            _connected("10.0.1.0/30", "Ethernet1/1", context_uid=p1_ctx),
        ],
        static=[_static("172.16.0.0/16", "10.0.1.2")],
        bgp=SimulationInput(
            processes=[
                _process("rp:r1:bgp", CTX, 65001, R1, redist_static_route_map=route_map),
                _process("rp:p1:bgp", p1_ctx, 65002, "10.255.1.1"),
            ],
            sessions=[
                _session(P1_SESSION, "rp:r1:bgp", 65001, 65002, "10.0.1.1", "10.0.1.2"),
                _session("bgp:p1:r1", "rp:p1:bgp", 65002, 65001, "10.0.1.2", "10.0.1.1"),
            ],
            policies=[RM_STATIC],
        ),
    )


def test_a_redistributed_static_appears_in_bgp_with_the_route_maps_attributes():
    result = rib.compute(_redistribution_input())
    assert result.bgp is not None
    in_bgp = [r for r in result.bgp.rib if r["context_uid"] == CTX and r["prefix"] == "172.16.0.0/16"]
    assert len(in_bgp) == 1
    assert in_bgp[0]["origin_mechanism"] == "redistribute"
    assert in_bgp[0]["origin"] == "incomplete"
    assert in_bgp[0]["local_pref"] == 300
    assert in_bgp[0]["communities"] == ["65001:100"]
    assert in_bgp[0]["weight"] == 32768
    # the main RIB keeps the static (administrative distance 1) and the peer
    # holds the advertisement
    assert _row(result, "172.16.0.0/16")["protocol"] == "static"
    peer = _row(result, "172.16.0.0/16", context_uid="vrf:p1:default")
    assert (peer["protocol"], peer["next_hop"], peer["as_path"], peer["origin"]) == (
        "bgp",
        "10.0.1.1",
        [65001],
        "incomplete",
    )
    assert result.model_errors == []


def test_a_redistribution_route_map_is_the_one_its_own_device_defines():
    """P1 defines its own `RM_STATIC`, which denies every route and is
    listed last. R1's redistribution runs through R1's `RM_STATIC`, not through
    the policy another device gave the same name."""
    inp = _redistribution_input()
    assert inp.bgp is not None
    inp.bgp.processes[0]["device_uid"] = DEV
    inp.bgp.processes[1]["device_uid"] = "dev:p1"
    inp.bgp.policies = [
        {**RM_STATIC, "device_uid": DEV},
        {
            "name": "RM_STATIC",
            "kind": "route-map",
            "device_uid": "dev:p1",
            "entries": [{"seq": 10, "kind": "clause", "action": "deny"}],
        },
    ]

    result = rib.compute(inp)

    assert result.bgp is not None
    in_bgp = [r for r in result.bgp.rib if r["context_uid"] == CTX and r["prefix"] == "172.16.0.0/16"]
    assert [r["local_pref"] for r in in_bgp] == [300]
    assert result.model_errors == []


def test_a_redistribution_route_map_is_the_one_its_own_virtual_system_defines():
    """R1 and P1 are two virtual systems of one gateway, and each
    defines a `RM_STATIC` in its own routing context. R1's redistribution runs
    through R1's (local preference 300), not through P1's, which denies every
    route."""
    inp = _redistribution_input()
    assert inp.bgp is not None
    for process in inp.bgp.processes:
        process["device_uid"] = DEV
    # P1's is listed last: one name-keyed compile keeps the last
    inp.bgp.policies = [
        {**RM_STATIC, "device_uid": DEV, "context_uid": CTX},
        {
            "name": "RM_STATIC",
            "kind": "route-map",
            "device_uid": DEV,
            "context_uid": "vrf:p1:default",
            "entries": [{"seq": 10, "kind": "clause", "action": "deny"}],
        },
    ]

    result = rib.compute(inp)

    assert result.bgp is not None
    in_bgp = [r for r in result.bgp.rib if r["context_uid"] == CTX and r["prefix"] == "172.16.0.0/16"]
    assert [r["local_pref"] for r in in_bgp] == [300]
    assert result.model_errors == []


def test_a_policy_one_device_does_not_define_is_undefined_for_it():
    """The route-map is named on R1 but only P1 defines it: R1 does not borrow
    P1's policy, and the undefined name is reported as it is for any name no
    RoutePolicy of the device defines."""
    inp = _redistribution_input()
    assert inp.bgp is not None
    inp.bgp.processes[0]["device_uid"] = DEV
    inp.bgp.processes[1]["device_uid"] = "dev:p1"
    inp.bgp.policies = [{**RM_STATIC, "device_uid": "dev:p1"}]

    result = rib.compute(inp)

    assert [e["kind"] for e in result.model_errors] == ["undefined-redistribute-route-map"]


def test_an_undefined_redistribution_route_map_follows_the_platforms_rule_and_is_reported():
    result = rib.compute(_redistribution_input(route_map="RM_ABSENT"))
    assert result.bgp is not None
    # NX-OS omits the undefined conjunct: the redistribution proceeds unfiltered
    assert [r["prefix"] for r in result.bgp.rib if r["context_uid"] == CTX] == ["172.16.0.0/16"]
    assert [e["kind"] for e in result.model_errors] == ["undefined-redistribute-route-map"]

    iosxe = _redistribution_input(route_map="RM_ABSENT")
    iosxe.contexts = [
        _ctx(platform="iosxe"),
        _ctx(uid="vrf:p1:default", device_uid="dev:p1", platform="iosxe"),
    ]
    for process in iosxe.bgp.processes:
        process["platform"] = "iosxe"
    dropped = rib.compute(iosxe)
    assert dropped.bgp is not None
    assert [r["prefix"] for r in dropped.bgp.rib if r["context_uid"] == CTX] == []


def test_bgp_is_redistributed_into_ospf_as_a_type_5_external_on_every_router_holding_the_asbr():
    """R1 redistributes BGP into OSPF. R2, whose database holds R1's router
    LSA, computes the BGP prefix as a type 2 external through R1."""
    r2_ctx = "vrf:r2:default"
    inp = _two_peer_input()
    inp.contexts = [_ctx(), _ctx(uid=r2_ctx, device_uid="dev:r2")]
    inp.connected = [
        *_r1_connected(),
        _connected("10.0.1.0/30", "Ethernet1/1"),
        _connected("10.0.2.0/30", "Ethernet1/2"),
        _connected("10.0.12.0/30", "Ethernet1/1", context_uid=r2_ctx),
    ]
    inp.ospf = [
        _ospf_entry(redist_bgp_route_map="RM_ALL"),
        _ospf_entry(context_uid=r2_ctx, router_id=R2, uid="rp:r2:ospf"),
    ]
    inp.bgp.policies.append(
        {
            "name": "RM_ALL",
            "kind": "route-map",
            "entries": [{"seq": 10, "kind": "clause", "action": "permit"}],
        }
    )
    result = rib.compute(inp)
    on_r2 = _row(result, "203.0.113.0/24", context_uid=r2_ctx)
    assert (on_r2["protocol"], on_r2["next_hop"], on_r2["path_type"], on_r2["metric"]) == (
        "ospf",
        "10.0.12.1",
        "external-2",
        20,
    )
    assert result.model_errors == []


# --- leaking ---------------------------------------------------------------------------


def test_a_leaked_route_resolves_in_the_exporting_context():
    """vrf:a exports a route target vrf:b imports. vrf:a's BGP selection
    (its own connected prefix and a path learned from a peer) reaches vrf:b
    with the next hop resolving in vrf:a, whose interface the FIB row names."""
    a, b = "vrf:r1:a", "vrf:r1:b"
    inp = rib.RibInput(
        contexts=[_ctx(uid=a, name="a"), _ctx(uid=b, name="b")],
        connected=[
            _connected("10.0.1.0/30", "Ethernet1/1", context_uid=a),
            _connected("192.168.10.0/24", "Ethernet1/2", context_uid=a),
            _connected("192.168.20.0/24", "Ethernet1/3", context_uid=b),
        ],
        bgp=SimulationInput(
            processes=[_process("rp:a", a, 65001, R1)],
            sessions=[_session(P1_SESSION, "rp:a", 65001, 65002, "10.0.1.1", "10.0.1.2")],
            local_routes=[{"process_uid": "rp:a", "prefix": "192.168.10.0/24", "src_protocol": "connected"}],
        ),
        observed_paths=[
            {**_path(P1_SESSION, "203.0.113.0/24", "10.0.1.2", as_path="65002"), "context_uid": a}
        ],
        direction_status={(P1_SESSION, "received"): "complete"},
        rt_pairs=[{"importer": b, "exporter": a, "via_rt": ["65001:1"]}],
    )
    result = rib.compute(inp)
    assert _rows(result, b) == [
        ("192.168.10.0/24", "bgp", None),
        ("192.168.20.0/24", "connected", None),
        ("203.0.113.0/24", "bgp", "10.0.1.2"),
    ]
    local = _row(result, "192.168.10.0/24", context_uid=b)
    assert local["next_hop_context_uid"] == a
    assert local["interface"] == "Ethernet1/2"
    assert local["leak_path"] == [a]
    learned = _row(result, "203.0.113.0/24", context_uid=b)
    assert learned["next_hop_context_uid"] == a
    assert learned["igp_cost"] == 0
    assert learned["as_path"] == [65002]
    # nothing leaks back into vrf:a, and the FIB scopes the leaked row's next hop
    assert _rows(result, a) == [
        ("10.0.1.0/30", "connected", None),
        ("192.168.10.0/24", "connected", None),
        ("203.0.113.0/24", "bgp", "10.0.1.2"),
    ]
    assert result.fib.lpm(DEV, b, "203.0.113.9")[0]["next_hop_context_uid"] == a
    assert result.model_errors == []


def test_a_static_route_leaked_through_next_hop_context_resolves_there():
    a, b = "vrf:r1:a", "vrf:r1:b"
    inp = rib.RibInput(
        contexts=[_ctx(uid=a, name="a"), _ctx(uid=b, name="b")],
        connected=[_connected("10.0.1.0/30", "Ethernet1/1", context_uid=a)],
        static=[_static("0.0.0.0/0", "10.0.1.2", context_uid=b, next_hop_context_uid=a)],
    )
    result = rib.compute(inp)
    row = _row(result, "0.0.0.0/0", context_uid=b)
    assert (row["protocol"], row["next_hop"], row["next_hop_context_uid"]) == ("static", "10.0.1.2", a)
    assert result.gaps == []


# --- the compiled FIB and the tracer -----------------------------------------------------

IF_ETH1 = "if:r1:eth1"
MAIN, T100 = "vrf:r1:main", "vrf:r1:100"


def _pbr_rule(**over):
    row = {
        "pol_uid": "pol:steer",
        "pol_name": "steer",
        "rule_uid": "rule:10",
        "pos": 10,
        "rule_name": None,
        "src_cidrs": ["10.0.0.0/24"],
        "src_ips": [],
        "src_ranges": [],
        "dst_cidrs": [],
        "dst_ips": [],
        "dst_ranges": [],
        "table_uid": T100,
        "table_name": "100",
        "svc_obj_count": 0,
        "svc_protos": [],
        "svc_port_specs": [],
        "svc_opaque": False,
        "svc_opaque_reasons": [],
        "svc_src_port": False,
        "svc_src_ports": [],
    }
    row.update(over)
    return row


def _fib_input():
    return rib.RibInput(
        contexts=[_ctx(uid=MAIN, name="main"), _ctx(uid=T100, name="100")],
        connected=[
            _connected("10.0.0.0/24", "eth1", context_uid=MAIN),
            _connected("172.16.0.0/30", "eth0", context_uid=MAIN),
            _connected("172.16.1.0/30", "wg0", context_uid=T100),
        ],
        static=[
            _static("0.0.0.0/0", "172.16.0.2", context_uid=MAIN),
            _static("0.0.0.0/0", "172.16.1.2", context_uid=T100),
            _static("10.9.9.0/24", None, interface=None, context_uid=MAIN, discard="blackhole"),
        ],
        pbr=[{"if_uid": IF_ETH1, "device_uid": DEV, "context_uid": MAIN, "rules": [_pbr_rule()]}],
    )


def _graph_rows(fib, table_uid):
    """The FIB's rows for one table in the shape the tracer's route read
    returns, so `_route_partition` can be given them as graph rows."""
    return [
        {
            "uid": None,
            "cidr": r["prefix"],
            "kind": "ORIGINATES" if r["protocol"] == "connected" else "STATIC_ROUTE",
            "next_hop": r["next_hop"],
            "ifname": r["interface"],
            "egress_uid": None,
            "egress_name": r["interface"],
            "derived": None,
            "via_rt": None,
            "rib": True,
            "next_hop_vrf": r["next_hop_context_uid"],
            "discard": r["discard"],
        }
        for r in fib.table(table_uid)
    ]


def test_a_pbr_redirect_in_the_compiled_fib_matches_the_tracers_answer(monkeypatch):
    """The FIB's forwarding decision for a flow arriving on eth1 is the same
    partition `gates/pbr._pbr_partition` makes over the same rule rows read
    from the graph, and the same longest-prefix winners
    `gates/routing._route_partition` picks over the same routes: the part the
    rule claims goes to table 100's default, the rest to main's, and a
    blackhole in main discards its part."""
    result = rib.compute(_fib_input())
    fib = result.fib
    rule_rows = [_pbr_rule()]

    def fake_read(session, query, **params):
        assert "PbrPolicy" in query and params["if_uid"] == IF_ETH1
        return rule_rows

    def fake_read_one(session, query, **params):
        assert "IN_VRF]-(i:Interface {uid: $if_uid})" in query
        return {"uid": MAIN}

    monkeypatch.setattr(pathmod, "_read", fake_read)
    monkeypatch.setattr(pathmod, "_read_one", fake_read_one)

    src = pathmod._intervals(["10.0.0.0/23"])
    dst = pathmod._intervals(["8.8.8.8", "10.9.9.7"])
    tracer_groups = pathmod._pbr_partition(None, pathmod._Trail(), IF_ETH1, src, dst)
    tracer = [
        (
            g["table_uid"],
            g["pos"],
            pathmod._to_cidrs(g["sources"]),
            [
                (
                    pathmod._to_cidrs(part),
                    sorted((w["cidr"], w["next_hop"], w.get("discard")) for w in winners),
                )
                for part, winners in _route_partition(_graph_rows(fib, g["table_uid"]), g["dst"])
            ],
        )
        for g in tracer_groups
    ]
    compiled = [
        (
            g["table_uid"],
            g["pos"],
            pathmod._to_cidrs(g["sources"]),
            [
                (part, sorted((w["cidr"], w["next_hop"], w.get("discard")) for w in winners))
                for part, winners in g["parts"]
            ],
        )
        for g in fib.forward(IF_ETH1, src, dst)
    ]
    assert compiled == tracer
    assert compiled == [
        (T100, 10, ["10.0.0.0/24"], [(["8.8.8.8/32", "10.9.9.7/32"], [("0.0.0.0/0", "172.16.1.2", None)])]),
        (
            MAIN,
            None,
            ["10.0.1.0/24"],
            [
                (["8.8.8.8/32"], [("0.0.0.0/0", "172.16.0.2", None)]),
                (["10.9.9.7/32"], [("10.9.9.0/24", None, "blackhole")]),
            ],
        ),
    ]


def test_the_fib_answers_the_ribsource_questions_in_the_side_store_row_shape():
    fib = rib.compute(_fib_input()).fib
    assert fib.available and not fib.approximate
    assert fib.has_rows(DEV) and not fib.has_rows("dev:other")
    assert fib.coverage(DEV) == "computed"
    hit = fib.lpm(DEV, MAIN, "10.0.0.7")
    assert [(r["prefix"], r["protocol"], r["interface"], r["fib"]) for r in hit] == [
        ("10.0.0.0/24", "connected", "eth1", True)
    ]
    assert fib.lpm("dev:other", MAIN, "10.0.0.7") == []
    assert [r["prefix"] for r in fib.routes(DEV, MAIN)] == ["0.0.0.0/0"]
    lo, hi = pathmod.addrsets._set_bounds(pathmod._intervals(["10.0.0.0/8"]))
    assert [r["prefix"] for r in fib.overlapping(DEV, MAIN, lo, hi, 0, 4)] == ["10.0.0.0/24", "10.9.9.0/24"]
    assert fib.overlapping(DEV, MAIN, lo, hi, 24, 4) == []
    assert fib.table("vrf:elsewhere") is None


# --- validation ----------------------------------------------------------------------------

# The observed rib rows of R1 in each platform's own protocol vocabulary.
_VOCABULARY = {
    "nxos": {"connected": "direct", "static": "static", "ospf": "ospf-1", "bgp": "bgp-65001"},
    "iosxe": {"connected": "connected", "static": "static", "ospf": "ospf", "bgp": "bgp"},
    "iosxr": {"connected": "connected", "static": "static", "ospf": "ospf", "bgp": "bgp"},
    "vyos": {"connected": "connected", "static": "static", "ospf": "ospf", "bgp": "bgp"},
}


def _validation_input(platform):
    words = _VOCABULARY[platform]
    inp = _two_peer_input()
    inp.contexts = [_ctx(platform=platform)]
    inp.connected = [
        *_r1_connected(),
        _connected("10.0.1.0/30", "Ethernet1/3"),
        _connected("10.0.2.0/30", "Ethernet1/4"),
    ]
    inp.static = [_static("172.16.0.0/16", "10.0.13.3")]
    inp.ospf = [_ospf_entry()]
    inp.observed_rib = {
        CTX: [
            _rib("10.0.1.0/30", "10.0.1.1", words["connected"]),
            _rib("10.0.2.0/30", "10.0.2.1", words["connected"]),
            _rib("10.0.12.0/30", "10.0.12.1", words["connected"]),
            _rib("10.0.13.0/30", "10.0.13.1", words["connected"]),
            _rib("10.255.0.1/32", None, "local"),
            _rib("10.255.0.2/32", "10.0.12.2", words["ospf"], 11),
            _rib("10.255.0.3/32", "10.0.13.3", words["ospf"], 21),
            _rib("192.168.2.0/24", "10.0.12.2", words["ospf"], 15),
            _rib("172.16.0.0/16", "10.0.13.3", words["static"]),
            _rib("203.0.113.0/24", "10.0.1.2", words["bgp"], 0),
        ]
    }
    inp.rib_coverage = {CTX: "complete"}
    return inp


@pytest.mark.parametrize("platform", sorted(_VOCABULARY))
def test_validation_against_an_observed_rib_fixture_per_platform_reports_validated(platform):
    result = rib.compute(_validation_input(platform))
    statuses = {(row["prefix"], row["status"]) for row in result.validation}
    assert statuses == {
        ("10.0.1.0/30", "validated"),
        ("10.0.2.0/30", "validated"),
        ("10.0.12.0/30", "validated"),
        ("10.0.13.0/30", "validated"),
        ("10.255.0.2/32", "validated"),
        ("10.255.0.3/32", "validated"),
        ("192.168.2.0/24", "validated"),
        ("172.16.0.0/16", "validated"),
        ("203.0.113.0/24", "validated"),
        # a local host route is no collector's protocol: the calculation makes
        # no claim about it, and never calls it a mismatch
        ("10.255.0.1/32", "not-observed"),
    }
    assert result.model_errors == []


def test_a_mismatch_against_the_observed_rib_is_a_model_error_never_accepted_silently():
    inp = _validation_input("nxos")
    for row in inp.observed_rib[CTX]:
        if row["prefix"] == "172.16.0.0/16":
            row["next_hop"] = "10.0.12.2"
    inp.observed_rib[CTX].append(_rib("10.200.0.0/16", "10.0.12.2", "static"))
    result = rib.compute(inp)
    by_prefix = {row["prefix"]: row for row in result.validation}
    assert by_prefix["172.16.0.0/16"]["status"] == "mismatch"
    assert by_prefix["10.200.0.0/16"]["status"] == "mismatch"
    assert [(e["kind"], e["subject"]) for e in result.model_errors] == [
        ("rib-route-mismatch", f"{CTX}/10.200.0.0/16"),
        ("rib-route-mismatch", f"{CTX}/172.16.0.0/16"),
    ]


def test_a_connected_route_absent_from_an_export_without_connected_rows_is_validated():
    """collectors/vyos.py `_rib_entries` exports no connected or local route:
    the connected prefixes are ORIGINATES edges only. The computed connected
    route then has no observed row, and that absence is the export contract,
    not a route the device dropped. The interface address is the observation;
    nothing is a mismatch, and the routing of the context stays an answer."""
    inp = _validation_input("vyos")
    inp.observed_rib[CTX] = [r for r in inp.observed_rib[CTX] if r["protocol"] not in ("connected", "local")]
    result = rib.compute(inp)
    by_prefix = {row["prefix"]: row for row in result.validation}
    for prefix in ("10.0.1.0/30", "10.0.2.0/30", "10.0.12.0/30", "10.0.13.0/30"):
        assert by_prefix[prefix]["status"] == "validated", prefix
        assert "interface address is the observation" in by_prefix[prefix]["detail"]
    assert by_prefix["172.16.0.0/16"]["status"] == "validated"
    assert result.model_errors == []


def test_a_connected_route_missing_beside_other_connected_rows_stays_a_mismatch():
    """An export that does hold connected rows and lacks one is a device that
    dropped the route (the interface is down), and the mismatch stands."""
    inp = _validation_input("nxos")
    inp.observed_rib[CTX] = [r for r in inp.observed_rib[CTX] if r["prefix"] != "10.0.13.0/30"]
    result = rib.compute(inp)
    by_prefix = {row["prefix"]: row for row in result.validation}
    assert by_prefix["10.0.13.0/30"]["status"] == "mismatch"
    assert "holds no route for it" in by_prefix["10.0.13.0/30"]["detail"]
    errors = [(e["kind"], e["subject"]) for e in result.model_errors]
    assert ("rib-route-mismatch", f"{CTX}/10.0.13.0/30") in errors


def test_a_peer_whose_paths_are_not_captured_yields_not_observed_not_an_inferred_answer():
    inp = _two_peer_input(observed=False)
    inp.observed_rib = {
        CTX: [
            _rib("10.0.1.0/30", "10.0.1.1", "direct"),
            _rib("10.0.2.0/30", "10.0.2.1", "direct"),
            _rib("203.0.113.0/24", "10.0.1.2", "bgp-65001", 0),
        ]
    }
    inp.rib_coverage = {CTX: "complete"}
    result = rib.compute(inp)
    assert [r["prefix"] for r in result.rib] == ["10.0.1.0/30", "10.0.2.0/30"]
    gaps = [g for g in result.gaps if g["kind"] == "not-observed"]
    assert sorted(g["session_uid"] for g in gaps) == [P1_SESSION, P2_SESSION]
    assert all("the routes it sends are not collected" in g["detail"] for g in gaps)
    assert {g["cause"] for g in gaps} == {"peer-supply-not-observed"}
    by_prefix = {row["prefix"]: row for row in result.validation}
    assert by_prefix["203.0.113.0/24"]["status"] == "not-observed"
    assert "incomplete" in by_prefix["203.0.113.0/24"]["detail"]
    # the BGP engine names the same missing input; nothing is a mismatch
    assert {e["kind"] for e in result.model_errors} == {"unpaired-bgp-session"}


def test_observed_static_rows_stand_in_where_the_platform_collects_no_static_configuration():
    inp = _two_peer_input()
    inp.observed_rib = {CTX: [_rib("172.16.0.0/16", "10.0.1.2", "static")]}
    inp.rib_coverage = {CTX: "complete"}
    result = rib.compute(inp)
    row = _row(result, "172.16.0.0/16")
    assert (row["protocol"], row["source"], row["next_hop"]) == ("static", "observed-static", "10.0.1.2")
    assert [(g["kind"], g["context_uid"]) for g in result.gaps if g["kind"] == "not-collected"] == [
        ("not-collected", CTX)
    ]


# --- scale -----------------------------------------------------------------------------------


def test_a_context_of_two_thousand_routes_installs_within_a_second():
    """A lookup masks the address once per prefix length present."""
    candidates: dict[str, dict[str, list[rib.Candidate]]] = {CTX: {}}
    for i in range(1000):
        a, b = divmod(i, 64)
        connected = f"10.{a}.{b * 4}.0/30"
        candidates[CTX][connected] = [
            rib.Candidate(CTX, connected, rib.CONNECTED, 0, 0, interface=f"e{i}", source="connected")
        ]
        static = f"172.16.{i >> 8}.{i & 255}/32"
        candidates[CTX][static] = [
            rib.Candidate(CTX, static, rib.STATIC, 1, 0, next_hop=f"10.{a}.{b * 4}.1", source="static")
        ]
    with cpu_time() as spent:
        table, unresolved = rib._install(candidates, ErrorSink())
    assert spent.seconds < 1.0
    assert unresolved == []
    assert len(table.installed()) == 2000
    assert [e.candidate.prefix for e in table.lpm(CTX, "10.0.4.1")] == ["10.0.4.0/30"]
    assert table.lpm(CTX, "10.0.4.1", exclude="10.0.4.0/30") == []


# --- determinism -----------------------------------------------------------------------------


def test_the_calculation_is_deterministic():
    reference = rib.compute(_validation_input("nxos"))
    for seed in range(4):
        shuffled = _validation_input("nxos")
        rng = random.Random(seed)
        for name in ("connected", "static", "observed_paths"):
            values = list(getattr(shuffled, name))
            rng.shuffle(values)
            setattr(shuffled, name, values)
        rows = list(shuffled.observed_rib[CTX])
        rng.shuffle(rows)
        shuffled.observed_rib = {CTX: rows}
        shuffled.ospf[0]["rows"] = rng.sample(shuffled.ospf[0]["rows"], len(shuffled.ospf[0]["rows"]))
        shuffled.bgp.sessions = rng.sample(list(shuffled.bgp.sessions), 2)
        again = rib.compute(shuffled)
        assert again.rib == reference.rib
        assert again.validation == reference.validation
        assert again.gaps == reference.gaps
        assert again.fib.rows() == reference.fib.rows()
    assert copy.deepcopy(reference.rib) == rib.compute(_validation_input("nxos")).rib


# --- locally originated BGP routes -------------------------------------------------------
#
# network, redistribute and aggregate originations install behind the IGPs
# (IOS-XE, IOS-XR and FRR 200, NX-OS 220), never at the eBGP distance 20.


def _local_origin_input(platform="nxos", local_routes=(), **process_extra):
    return rib.RibInput(
        contexts=[_ctx(platform=platform)],
        connected=_r1_connected(),
        ospf=[_ospf_entry()],
        bgp=SimulationInput(
            processes=[_process("rp:r1:bgp", CTX, 65001, R1, platform=platform, **process_extra)],
            sessions=[],
            local_routes=[dict(r) for r in local_routes],
        ),
    )


@pytest.mark.parametrize(
    ("platform", "expected"),
    [
        (platforms.IOSXE, 200),
        (platforms.IOSXR, 200),
        (platforms.NXOS, 220),
        (platforms.FRR_TRADITIONAL, 200),
        (platforms.FRR_DATACENTER, 200),
    ],
)
def test_the_local_bgp_distance_per_platform(platform, expected):
    assert platforms.admin_distance(platform, platforms.LOCAL_BGP) == expected


@pytest.mark.parametrize("platform", [platforms.IOSXE, platforms.NXOS, platforms.IOSXR])
def test_a_network_statement_for_an_ospf_prefix_settles_with_ospf_installed(platform):
    network = {
        "intent": True,
        "process_uid": "rp:r1:bgp",
        "prefix": "192.168.2.0/24",
        "origin_mechanism": "network",
    }
    result = rib.compute(_local_origin_input(platform, local_routes=[network], network_import_check=True))
    assert result.model_errors == []
    row = _row(result, "192.168.2.0/24")
    assert (row["protocol"], row["admin"]) == ("ospf", 110)


def test_a_redistribution_of_ospf_into_bgp_settles_with_ospf_installed():
    result = rib.compute(_local_origin_input(redistribute_protocols=["ospf"]))
    assert result.model_errors == []
    assert _row(result, "192.168.2.0/24")["protocol"] == "ospf"
    assert result.bgp is not None
    held = [r for r in result.bgp.rib if r["prefix"] == "192.168.2.0/24"]
    assert [r["origin_mechanism"] for r in held] == ["redistribute"]


@pytest.mark.parametrize(
    ("platform", "admin"), [(platforms.IOSXE, 200), (platforms.NXOS, 220), (platforms.IOSXR, 200)]
)
def test_an_aggregate_installs_as_a_discard_route_at_the_local_distance(platform, admin):
    local_routes = [
        {"process_uid": "rp:r1:bgp", "prefix": "10.0.0.0/8", "origin_mechanism": "aggregate"},
        {"process_uid": "rp:r1:bgp", "prefix": "10.1.0.0/16", "origin_mechanism": "network"},
    ]
    result = rib.compute(_local_origin_input(platform, local_routes=local_routes))
    row = _row(result, "10.0.0.0/8")
    assert (row["protocol"], row["admin"], row["next_hop"], row["discard"]) == (
        "bgp",
        admin,
        None,
        "blackhole",
    )
    assert _row(result, "10.1.0.0/16")["discard"] is None


# --- MED before eBGP over iBGP -----------------------------------------------------------


def _med_input(*, p2_asn, p2_as_path, p2_med, always_compare_med=False):
    inp = _two_peer_input()
    inp.bgp.policies = []
    inp.bgp.sessions[0].pop("import_policy_name")
    inp.bgp.sessions[0].pop("import_policy_kind")
    inp.bgp.sessions[1]["peer_asn"] = p2_asn
    inp.bgp.processes[0]["always_compare_med"] = always_compare_med
    inp.observed_paths = [
        _path(P1_SESSION, "203.0.113.0/24", "10.0.1.2", as_path="65002", med=100),
        _path(P2_SESSION, "203.0.113.0/24", "10.0.2.2", as_path=p2_as_path, med=p2_med),
    ]
    return inp


def test_the_ibgp_path_with_the_lower_med_wins_over_the_ebgp_path_from_the_same_as():
    result = rib.compute(_med_input(p2_asn=65001, p2_as_path="65002", p2_med=50))
    row = _row(result, "203.0.113.0/24")
    assert (row["next_hop"], row["med"], row["learned_from_session"]) == ("10.0.2.2", 50, P2_SESSION)


def test_always_compare_med_lets_the_lower_med_win_across_neighbouring_ases():
    inp = _med_input(p2_asn=65003, p2_as_path="65003", p2_med=10, always_compare_med=True)
    row = _row(rib.compute(inp), "203.0.113.0/24")
    assert (row["next_hop"], row["med"]) == ("10.0.2.2", 10)
    gated = _med_input(p2_asn=65003, p2_as_path="65003", p2_med=10)
    assert _row(rib.compute(gated), "203.0.113.0/24")["next_hop"] == "10.0.1.2", (
        "without the knob the MED step is skipped and the earlier session wins on arrival order"
    )


# --- OSPF external regeneration keeps what the model does not explain -------------------

R2_CTX = "vrf:r2:default"


def _external(prefix_text, adv_router=R1, metric=1, metric_type=2):
    net = ipaddress.ip_network(prefix_text)
    return _lsa(
        "external",
        str(net.network_address),
        adv_router,
        area=None,
        mask=str(net.netmask),
        metric=metric,
        metric_type=metric_type,
        forwarding_address="0.0.0.0",  # noqa: S104 - an LSA field, not a bind address
    )


def _externals_input(external_rows, r1_ospf=None, static=(), observed_rib=None, bgp=False):
    """R1 (calculating router, with `r1_ospf` merged into its OSPF process) and
    R2 on one database carrying `external_rows`; the result is read on R2."""
    rows = [*_lsdb(), *external_rows]
    inp = rib.RibInput(
        contexts=[_ctx(), _ctx(uid=R2_CTX, device_uid="dev:r2")],
        connected=[
            *_r1_connected(),
            _connected("10.0.12.0/30", "Ethernet1/1", context_uid=R2_CTX),
        ],
        static=list(static),
        ospf=[
            _ospf_entry(rows=rows, **(r1_ospf or {})),
            _ospf_entry(context_uid=R2_CTX, router_id=R2, uid="rp:r2:ospf", rows=rows),
        ],
        observed_rib=observed_rib or {},
    )
    if bgp:
        inp.bgp = SimulationInput(
            processes=[_process("rp:r1:bgp", CTX, 65001, R1)], sessions=[], policies=[], local_routes=[]
        )
    return inp


def _on_r2(result, prefix):
    return [r for r in result.rib if r["context_uid"] == R2_CTX and r["prefix"] == prefix]


def test_an_observed_default_lsa_survives_a_redistribution_that_does_not_explain_it():
    """R1 originates 0/0 through `default-information originate`, which is
    not what its `redistribute connected` statement produces; the statement must not
    delete the observed LSA."""
    inp = _externals_input(
        [_external("0.0.0.0/0")],
        r1_ospf={"redistribute": [{"protocol": "connected", "route_map": None}]},
    )
    result = rib.compute(inp)
    default = _on_r2(result, "0.0.0.0/0")
    assert [(r["protocol"], r["metric"], r["next_hop"]) for r in default] == [("ospf", 1, "10.0.12.1")]


def test_a_static_default_is_not_redistributed_into_ospf():
    inp = _externals_input(
        [],
        r1_ospf={"redistribute": [{"protocol": "static", "route_map": None}]},
        static=[
            _static("0.0.0.0/0", "10.0.1.254", interface="Ethernet1/3"),
            _static("172.16.0.0/16", "10.0.1.254"),
        ],
    )
    result = rib.compute(inp)
    assert _on_r2(result, "0.0.0.0/0") == []
    assert [r["path_type"] for r in _on_r2(result, "172.16.0.0/16")] == ["external-2"]


def test_a_statement_the_engine_cannot_model_leaves_the_routers_observed_externals_alone():
    inp = _externals_input(
        [_external("198.51.100.0/24"), _external("0.0.0.0/0")],
        r1_ospf={"redistribute": [{"protocol": "eigrp", "route_map": None}]},
    )
    result = rib.compute(inp)
    assert [r["path_type"] for r in _on_r2(result, "198.51.100.0/24")] == ["external-2"]
    assert len(_on_r2(result, "0.0.0.0/0")) == 1
    assert [e["kind"] for e in result.model_errors] == ["redistribution-not-modeled"]
    assert not [g for g in result.gaps if g.get("prefix") == "198.51.100.0/24"]


def test_an_observed_external_a_recorded_statement_explains_is_replaced_and_the_rest_is_kept_with_a_gap():
    """R1 redistributes BGP; its observed RIB holds 203.0.113.0/24 as a BGP route, so
    that LSA is the statement's output and goes when the route is not in BGP any
    more. 198.51.100.0/24 has no explanation among R1's statements: it stays, and the
    result names it."""
    observed = {CTX: [_rib("203.0.113.0/24", "10.0.1.2", "bgp")]}
    inp = _externals_input(
        [_external("203.0.113.0/24", metric=1), _external("198.51.100.0/24", metric=7)],
        r1_ospf={"redistribute": [{"protocol": "bgp", "route_map": None}]},
        observed_rib=observed,
        bgp=True,
    )
    result = rib.compute(inp, validate_observed=False)
    assert _on_r2(result, "203.0.113.0/24") == []
    kept = _on_r2(result, "198.51.100.0/24")
    assert [(r["protocol"], r["metric"]) for r in kept] == [("ospf", 7)]
    gaps = [g for g in result.gaps if g.get("prefix") == "198.51.100.0/24"]
    # the router's own context, and the context that reads its LSA
    assert sorted((g["kind"], g["context_uid"], g["scope"]) for g in gaps) == [
        ("not-observed", CTX, "prefix"),
        ("not-observed", R2_CTX, "prefix"),
    ]


@pytest.mark.parametrize(
    ("r1_ospf", "static", "kept", "gap"),
    [
        ({"default_information_originate": True}, [], False, False),
        (
            {"default_information_originate": True},
            [_static("0.0.0.0/0", "10.0.1.254", interface="Ethernet1/3")],
            True,
            False,
        ),
        (
            {"default_information_originate": True, "default_information_originate_always": True},
            [],
            True,
            False,
        ),
        ({}, [], True, True),
    ],
    ids=["conditional-without-default", "conditional-with-default", "always", "not-recorded"],
)
def test_the_default_lsa_follows_default_information_originate(r1_ospf, static, kept, gap):
    inp = _externals_input([_external("0.0.0.0/0")], r1_ospf=r1_ospf, static=static)
    result = rib.compute(inp)
    assert bool(_on_r2(result, "0.0.0.0/0")) is kept
    assert bool([g for g in result.gaps if g.get("prefix") == "0.0.0.0/0"]) is gap


# --- default routes in a BGP redistribution ----------------------------------------------


def _default_redistribution_input(platform, **process_extra):
    """R1 holds a static default and a static 172.16.0.0/16 and redistributes
    static into BGP with no route-map."""
    inp = _redistribution_input(route_map=None)
    inp.platform = platform
    inp.contexts = [
        _ctx(platform=platform),
        _ctx(uid="vrf:p1:default", device_uid="dev:p1", platform=platform),
    ]
    inp.static = [_static("0.0.0.0/0", "10.0.1.2"), _static("172.16.0.0/16", "10.0.1.2")]
    for process in inp.bgp.processes:
        process["platform"] = platform
    inp.bgp.processes[0]["redistribute_protocols"] = ["static"]
    inp.bgp.processes[0].update(process_extra)
    return inp


def _bgp_prefixes(result):
    assert result.bgp is not None
    return sorted(r["prefix"] for r in result.bgp.rib if r["context_uid"] == CTX)


@pytest.mark.parametrize("platform", [platforms.IOSXE, platforms.IOSXR, platforms.NXOS])
def test_a_default_route_is_not_redistributed_into_bgp_without_default_information_originate(platform):
    result = rib.compute(_default_redistribution_input(platform, origin_config_recorded=True))
    assert _bgp_prefixes(result) == ["172.16.0.0/16"]
    assert [g for g in result.gaps if g.get("prefix") == "0.0.0.0/0"] == []


@pytest.mark.parametrize("platform", [platforms.IOSXE, platforms.IOSXR, platforms.NXOS])
def test_default_information_originate_lets_the_default_route_into_bgp(platform):
    inp = _default_redistribution_input(
        platform, origin_config_recorded=True, default_information_originate_afs=[4]
    )
    result = rib.compute(inp)
    assert _bgp_prefixes(result) == ["0.0.0.0/0", "172.16.0.0/16"]


def test_a_skipped_default_route_is_a_gap_where_the_process_configuration_was_not_recorded():
    result = rib.compute(_default_redistribution_input(platforms.IOSXE))
    assert _bgp_prefixes(result) == ["172.16.0.0/16"]
    gaps = [g for g in result.gaps if g.get("prefix") == "0.0.0.0/0"]
    # the originating context and the peer that would have received the route
    assert {(g["kind"], g["context_uid"]) for g in gaps} == {
        ("not-observed", CTX),
        ("not-observed", "vrf:p1:default"),
    }
    assert "default-information originate was not recorded" in gaps[0]["detail"]


def test_a_default_route_is_a_gap_where_the_platform_rule_is_not_established():
    result = rib.compute(
        _default_redistribution_input(platforms.FRR_TRADITIONAL, origin_config_recorded=True)
    )
    assert _bgp_prefixes(result) == ["172.16.0.0/16"]
    gaps = [g for g in result.gaps if g.get("prefix") == "0.0.0.0/0"]
    assert {(g["kind"], g["context_uid"]) for g in gaps} == {
        ("not-observed", CTX),
        ("not-observed", "vrf:p1:default"),
    }
    assert "not established" in gaps[0]["detail"]


# --- next-hop-self across an iBGP session ------------------------------------------------
#
# R1 (AS 65001) learns 203.0.113.0/24 from an ISP over a link that is not in the IGP and
# advertises it to R2 over iBGP between loopbacks. R2 reaches R1's loopback through a
# static route and has no route to the ISP's address.

ISP_SESSION, R1_R2, R2_R1 = "bgp:r1:isp", "bgp:r1:r2", "bgp:r2:r1"


def _next_hop_self_input(next_hop_self=None):
    r1_session = _session(R1_R2, "rp:r1:bgp", 65001, 65001, R1, R2)
    if next_hop_self:
        r1_session["next_hop_self"] = next_hop_self
    paths = [_path(ISP_SESSION, "203.0.113.0/24", "192.0.2.1", as_path="65100")]
    return rib.RibInput(
        contexts=[_ctx(), _ctx(uid=R2_CTX, device_uid="dev:r2")],
        connected=[
            _connected("192.0.2.0/30", "Ethernet1/3"),
            _connected("10.0.12.0/30", "Ethernet1/1"),
            _connected("10.255.0.1/32", "loopback0"),
            _connected("10.0.12.0/30", "Ethernet1/1", context_uid=R2_CTX),
            _connected("10.255.0.2/32", "loopback0", context_uid=R2_CTX),
        ],
        static=[
            _static("10.255.0.1/32", "10.0.12.1", context_uid=R2_CTX),
            _static("10.255.0.2/32", "10.0.12.2"),
        ],
        bgp=SimulationInput(
            processes=[
                _process("rp:r1:bgp", CTX, 65001, R1),
                _process("rp:r2:bgp", R2_CTX, 65001, R2),
            ],
            sessions=[
                _session(ISP_SESSION, "rp:r1:bgp", 65001, 65100, "192.0.2.2", "192.0.2.1"),
                r1_session,
                _session(R2_R1, "rp:r2:bgp", 65001, 65001, R2, R1),
            ],
        ),
        observed_paths=paths,
        direction_status={(ISP_SESSION, "received"): "complete", (ISP_SESSION, "accepted"): "not-captured"},
        platform="nxos",
    )


def test_next_hop_self_lets_the_ibgp_peer_install_a_route_whose_external_next_hop_it_cannot_reach():
    result = rib.compute(_next_hop_self_input("ebgp"))
    row = _row(result, "203.0.113.0/24", context_uid=R2_CTX)
    assert (row["protocol"], row["next_hop"]) == ("bgp", R1)
    assert [
        g for g in result.gaps if g["kind"] == "not-observed" and g.get("prefix") == "203.0.113.0/24"
    ] == []


def test_without_next_hop_self_the_unresolved_external_next_hop_is_a_named_gap():
    result = rib.compute(_next_hop_self_input())
    assert _rows(result, context_uid=R2_CTX) == [
        ("10.0.12.0/30", "connected", None),
        ("10.255.0.1/32", "static", "10.0.12.1"),
        ("10.255.0.2/32", "connected", None),
    ]
    gaps = [g for g in result.gaps if g["kind"] == "not-observed" and g.get("prefix") == "203.0.113.0/24"]
    assert (R2_CTX, "prefix", R2_R1) in [(g["context_uid"], g["scope"], g["session_uid"]) for g in gaps]
    assert "next-hop-self is not recorded" in gaps[0]["detail"]


def test_an_aggregate_discard_route_validates_against_the_observed_null0_row():
    local_routes = [
        {"process_uid": "rp:r1:bgp", "prefix": "10.0.0.0/8", "origin_mechanism": "aggregate"},
        {"process_uid": "rp:r1:bgp", "prefix": "10.1.0.0/16", "origin_mechanism": "network"},
    ]
    inp = _local_origin_input(platforms.IOSXE, local_routes=local_routes)
    inp.observed_rib = {CTX: [_rib("10.0.0.0/8", None, "bgp", 0, interface="Null0")]}
    inp.rib_coverage = {CTX: "complete"}
    result = rib.compute(inp)
    by_prefix = {row["prefix"]: row for row in result.validation}
    assert by_prefix["10.0.0.0/8"]["status"] == "validated"


def _fib_with(rule: dict):
    fib_input = _fib_input()
    fib_input = rib.RibInput(
        contexts=fib_input.contexts,
        connected=fib_input.connected,
        static=fib_input.static,
        pbr=[{"if_uid": IF_ETH1, "device_uid": DEV, "context_uid": MAIN, "rules": [rule]}],
    )
    return rib.compute(fib_input).fib


def test_the_compiled_fib_pbr_read_returns_the_family_and_object_counts():
    """`partition_rules` reads `pol_af` and the object counts; the compiled
    FIB's own copy of the PBR read returns them."""
    from hst.app.simul_read import _PBR_BINDINGS

    returned = _PBR_BINDINGS.split("RETURN DISTINCT", 1)[1]
    for column in ("pol.af AS pol_af", "src_obj_count", "dst_obj_count"):
        assert column in returned
    assert "count(DISTINCT so) AS src_obj_count" in _PBR_BINDINGS
    assert "count(DISTINCT dobj) AS dst_obj_count" in _PBR_BINDINGS


def test_an_ipv4_policy_route_claims_no_ipv6_flow_in_the_compiled_fib():
    fib = _fib_with(_pbr_rule(src_cidrs=[], pol_af=4))
    v6 = fib.partition(IF_ETH1, pathmod._intervals(["2001:db8::5"]), pathmod._intervals(["2001:db8:1::9"]))
    assert [g["rule_uid"] for g in v6] == [None]
    v4 = fib.partition(IF_ETH1, pathmod._intervals(["10.0.0.5"]), pathmod._intervals(["8.8.8.8"]))
    assert [(g["rule_uid"], g["table_uid"]) for g in v4] == [("rule:10", T100)]


def test_a_policy_route_without_af_claims_every_family_in_the_compiled_fib():
    fib = _fib_with(_pbr_rule(src_cidrs=[], pol_af=None))
    v6 = fib.partition(IF_ETH1, pathmod._intervals(["2001:db8::5"]), pathmod._intervals(["2001:db8:1::9"]))
    assert [(g["rule_uid"], g["table_uid"]) for g in v6] == [("rule:10", T100)]
