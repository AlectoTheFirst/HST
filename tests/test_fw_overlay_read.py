"""`hst.path._read` is the package's monkeypatch seam."""

from typing import Any

import pytest

from hst import path as pathmod
from hst.app import fw_overlay_read, simul_read
from hst.simul import provider
from hst.simul.fw_overlay import ProposalError
from hst.simul.propagate import RouteDelta


class _Graph:
    """A fake `path._read`: one canned answer per query, keyed by a fragment."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, session: Any, query: str, **params: Any) -> Any:
        self.calls.append((query, params))
        for fragment, rows in self.answers.items():
            if fragment in query:
                return rows(params) if callable(rows) else list(rows)
        return []


def _install(monkeypatch: pytest.MonkeyPatch, answers: dict[str, Any]) -> _Graph:
    graph = _Graph(answers)
    monkeypatch.setattr(pathmod, "_read", graph)
    return graph


CATALOG_ROWS: dict[str, Any] = {
    "MATCH (o:NetObject:Obj)": [
        {
            "uid": "no:servers",
            "name": "SERVERS",
            "ranges": ["10.4.0.1-10.4.0.9"],
            "addrs": ["10.3.0.0/24"],
            "members": [],
        }
    ],
    "MATCH (s:SvcObject:Obj)": [{"uid": "so:web", "name": "WEB", "proto": "tcp", "ports": ["443"]}],
    "MATCH (z:Zone:Obj)": [
        {"uid": "zone:lan", "name": "LAN", "interface_names": ["eth0"], "interface_uids": ["if:eth0"]}
    ],
}

DENY = {
    "kind": "fw_rule.add",
    "params": {
        "rulebase": "fw:LAN",
        "position": 10,
        "action": "drop",
        "source": "any",
        "destination": ["192.168.2.35", "192.168.2.36"],
    },
}


def _fake_trace(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Replace the tracer with one that says which session it was handed."""
    seen: list[Any] = []

    def trace(
        session: Any,
        src: str,
        dst: str,
        port: Any = None,
        proto: str = "tcp",
        rib: Any = None,
        gateways: Any = None,
    ) -> dict[str, Any]:
        seen.append(session)
        overlaid = isinstance(session, fw_overlay_read.OverlaySession)
        return {
            "verdict": ("BLOCKED by LAN policy rule 10" if overlaid else f"permitted {src}->{dst}"),
            "indeterminate": False,
            "warnings": ["a warning the tracer raised"],
            "legs": [{"firewall": "LAN policy (device) drop by rule 10", "blocked": overlaid}],
        }

    monkeypatch.setattr(pathmod, "trace", trace)
    return seen


def test_every_flow_is_traced_twice_and_the_second_trace_is_the_overlaid_one(monkeypatch):
    _install(monkeypatch, CATALOG_ROWS)
    seen = _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "192.168.2.35", "port": 443}]
    )
    assert len(seen) == 2
    assert not isinstance(seen[0], fw_overlay_read.OverlaySession)
    assert isinstance(seen[1], fw_overlay_read.OverlaySession)

    flow = body["flows"][0]
    assert flow["before"]["blocked"] is False
    assert flow["after"]["blocked"] is True
    assert flow["result_changed"] is True
    assert flow["blocked_changed"] is True
    assert body["results_changed"] == 1
    # the tracer's own warnings survive into the answer on both sides
    assert flow["before"]["warnings"] == ["a warning the tracer raised"]
    assert flow["after"]["decided_by"] == ["LAN policy (device) drop by rule 10"]


def _fake_trace_recording_rib(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Like `_fake_trace`, but records the `rib` kwarg each call received."""
    ribs: list[Any] = []

    def trace(
        session: Any,
        src: str,
        dst: str,
        port: Any = None,
        proto: str = "tcp",
        rib: Any = None,
        gateways: Any = None,
    ) -> dict[str, Any]:
        ribs.append(rib)
        overlaid = isinstance(session, fw_overlay_read.OverlaySession)
        return {
            "verdict": ("BLOCKED by LAN policy rule 10" if overlaid else f"permitted {src}->{dst}"),
            "indeterminate": False,
            "warnings": ["a warning the tracer raised"],
            "legs": [{"firewall": "LAN policy (device) drop by rule 10", "blocked": overlaid}],
        }

    monkeypatch.setattr(pathmod, "trace", trace)
    return ribs


def test_simulate_change_threads_its_rib_into_both_the_before_and_after_trace(monkeypatch):
    """simulate_change builds no RibSource itself."""
    _install(monkeypatch, CATALOG_ROWS)
    ribs = _fake_trace_recording_rib(monkeypatch)
    sentinel = object()
    fw_overlay_read.simulate_change(
        object(),
        intents=[DENY],
        flows=[{"src": "10.0.0.5", "dst": "192.168.2.35", "port": 443}],
        rib=sentinel,
    )
    assert ribs == [sentinel, sentinel]


def test_the_proposal_is_echoed_back_as_the_intents_that_were_evaluated(monkeypatch):
    _install(monkeypatch, CATALOG_ROWS)
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}]
    )
    assert body["intents"] == [DENY]


def test_a_netobject_named_in_prose_is_resolved_from_the_snapshot(monkeypatch):
    _install(monkeypatch, CATALOG_ROWS)
    _fake_trace(monkeypatch)
    intent = {
        "kind": "fw_rule.add",
        "params": {
            "rulebase": "fw:LAN",
            "position": 10,
            "action": "drop",
            "source": "any",
            "destination": "SERVERS",
        },
    }
    body = fw_overlay_read.simulate_change(
        object(), intents=[intent], flows=[{"src": "10.0.0.5", "dst": "10.3.0.7"}]
    )
    assert body["flow_count"] == 1
    catalog = fw_overlay_read.read_catalog(object(), [intent])
    assert sorted(catalog.net_addresses("SERVERS")) == ["10.3.0.0/24", "10.4.0.1-10.4.0.9"]


def test_the_zone_catalog_carries_the_unreported_state_rules_marker(monkeypatch):
    """The zone read returns `established_default_unknown` and the
    catalog keeps it, so a zone move hands the tracer's fall-through the same
    marker the collected zone carries."""
    graph = _install(
        monkeypatch,
        {
            "MATCH (z:Zone:Obj)": [
                {
                    "uid": "zone:guest",
                    "name": "GUEST",
                    "default_action": "drop",
                    "default_action_unknown": False,
                    "established_default_unknown": True,
                    "interface_names": [],
                    "interface_uids": [],
                }
            ]
        },
    )

    catalog = fw_overlay_read.read_catalog(
        object(), [{"kind": "zone.add_interface", "params": {"zone": "GUEST", "interface": "if:eth9"}}]
    )

    (zone_query,) = [q for q, _ in graph.calls if "MATCH (z:Zone:Obj)" in q]
    assert "z.established_default_unknown AS established_default_unknown" in zone_query
    assert catalog.zones["zone:guest"]["established_default_unknown"] is True


def test_a_change_set_that_cannot_be_applied_is_raised_not_answered(monkeypatch):
    _install(monkeypatch, CATALOG_ROWS)
    _fake_trace(monkeypatch)
    bad = {
        "kind": "fw_rule.add",
        "params": {
            "rulebase": "fw:LAN",
            "position": 10,
            "action": "drop",
            "source": "any",
            "destination": "no-such-object",
        },
    }
    with pytest.raises(ProposalError):
        fw_overlay_read.simulate_change(object(), intents=[bad], flows=[{"src": "a", "dst": "b"}])


def test_a_flow_missing_an_endpoint_is_refused(monkeypatch):
    _install(monkeypatch, CATALOG_ROWS)
    _fake_trace(monkeypatch)
    with pytest.raises(ProposalError, match="needs a src and a dst"):
        fw_overlay_read.simulate_change(object(), intents=[DENY], flows=[{"src": "10.0.0.5"}])


# --- the routing follow-on -------------------------------------------------

ROUTE_ROWS: dict[str, Any] = {
    **CATALOG_ROWS,
    "MATCH (rp:RoutingProcess)-[h:HAS]->(b:BgpSession:Obj)": [
        {
            "uid": "bgp:a:1",
            "peer_ip": "192.168.2.35",
            "peer_asn": 65002,
            "local_asn": 65001,
            "process_uid": "rp:a",
            "context_uid": "vrf:a:default",
        },
        {
            "uid": "bgp:a:2",
            "peer_ip": "10.7.0.1",
            "peer_asn": 65003,
            "local_asn": 65001,
            "process_uid": "rp:a",
            "context_uid": "vrf:a:default",
        },
    ],
    "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": [
        {
            "kind": "LEARNED_ROUTE",
            "prefix": "203.0.113.0/24",
            "next_hop": "192.168.2.35",
            "protocol": "bgp",
            "context_uid": "vrf:a:default",
        }
    ],
}


def _install_route_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provider 2 is replaced by a stand-in that answers from its input, so what
    is under test is the withholding and the diff, not the engine."""

    def read_input(session: Any, **kw: Any) -> simul_read.GraphInput:
        return simul_read.GraphInput(
            processes=[{"uid": "rp:a", "context_uid": "vrf:a:default"}],
            sessions=[{"uid": "bgp:a:1"}, {"uid": "bgp:a:2"}],
        )

    def compute(*, processes, sessions, policies, local_routes, platform) -> RouteDelta:
        uids = {s["uid"] for s in sessions}
        rib = [{"context_uid": "vrf:a:default", "prefix": "10.0.0.0/8", "next_hop": "10.7.0.1"}]
        if "bgp:a:1" in uids:
            rib.append(
                {"context_uid": "vrf:a:default", "prefix": "203.0.113.0/24", "next_hop": "192.168.2.35"}
            )
        return RouteDelta(rib=rib, model_errors=[])

    monkeypatch.setattr(simul_read, "read_simulation_input", read_input)
    monkeypatch.setattr(provider, "compute_route_delta", compute)


def test_denying_a_peers_address_names_the_peering_and_the_prefixes_it_carried(monkeypatch):
    """Naming a BGP peer's address in a deny is an address dependency, not a
    session shutdown: the peering and the routes it carries are named, but
    nothing predicts the session going down."""
    _install(monkeypatch, ROUTE_ROWS)
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}]
    )
    routing = body["routing_consequence"]
    assert routing["evaluation"] == "address-dependency"
    assert [s["uid"] for s in routing["bgp_sessions_to_a_denied_address"]] == ["bgp:a:1"]
    assert routing["bgp_sessions_to_a_denied_address_note"]
    assert routing["implied_intents"] == []
    assert [r["prefix"] for r in routing["recorded_routes_via_a_denied_next_hop"]] == ["203.0.113.0/24"]
    # no control-plane evaluation ran, so nothing is predicted withdrawn
    assert routing["predicted_prefixes_withdrawn"] == []
    assert routing["scopes_predicted"] == []


def test_a_service_specific_deny_implies_no_session_shutdown(monkeypatch):
    """`denied_directions()` collects an address without reading service."""
    _install(monkeypatch, ROUTE_ROWS)
    _fake_trace(monkeypatch)
    tcp_80_only = {
        "kind": "fw_rule.add",
        "params": {
            "rulebase": "fw:LAN",
            "position": 10,
            "action": "drop",
            "source": "any",
            "destination": "192.168.2.35",
            "protocols": "tcp",
            "ports": "80",
        },
    }
    body = fw_overlay_read.simulate_change(
        object(), intents=[tcp_80_only], flows=[{"src": "10.0.0.5", "dst": "192.168.2.35", "port": 80}]
    )
    routing = body["routing_consequence"]
    assert [s["uid"] for s in routing["bgp_sessions_to_a_denied_address"]] == ["bgp:a:1"]
    assert routing["implied_intents"] == []
    assert routing["predicted_prefixes_withdrawn"] == []


def test_a_shadowed_deny_implies_no_session_shutdown(monkeypatch):
    """The overlay does not evaluate shadowing."""
    _install(monkeypatch, ROUTE_ROWS)
    _fake_trace(monkeypatch)
    shadowing_permit = {
        "kind": "fw_rule.add",
        "params": {
            "rulebase": "fw:LAN",
            "position": 1,
            "action": "permit",
            "source": "any",
            "destination": "192.168.2.35",
        },
    }
    shadowed_deny = {
        "kind": "fw_rule.add",
        "params": {
            "rulebase": "fw:LAN",
            "position": 10,
            "action": "drop",
            "source": "any",
            "destination": "192.168.2.35",
        },
    }
    body = fw_overlay_read.simulate_change(
        object(),
        intents=[shadowing_permit, shadowed_deny],
        flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}],
    )
    routing = body["routing_consequence"]
    assert [s["uid"] for s in routing["bgp_sessions_to_a_denied_address"]] == ["bgp:a:1"]
    assert routing["implied_intents"] == []
    assert routing["predicted_prefixes_withdrawn"] == []


def test_an_off_path_deny_implies_no_session_shutdown(monkeypatch):
    """The denied address is a BGP peer's, but no recorded route uses it as a next hop."""
    _install(monkeypatch, ROUTE_ROWS)
    _fake_trace(monkeypatch)
    off_path = {
        "kind": "fw_rule.add",
        "params": {
            "rulebase": "fw:LAN",
            "position": 10,
            "action": "drop",
            "source": "any",
            "destination": "10.7.0.1",
        },
    }
    body = fw_overlay_read.simulate_change(
        object(), intents=[off_path], flows=[{"src": "10.0.0.5", "dst": "10.7.0.1"}]
    )
    routing = body["routing_consequence"]
    assert [s["uid"] for s in routing["bgp_sessions_to_a_denied_address"]] == ["bgp:a:2"]
    assert routing["next_hop_withdrawal"] is None
    assert routing["implied_intents"] == []


def test_a_deny_in_an_overlapping_vrf_implies_no_session_shutdown(monkeypatch):
    """The same peer address literal recurs in a second VRF (overlapping
    addressing); a deny matches both sessions by address alone, and neither is
    implied shut without a context-scoped control-plane evaluation."""
    rows = {
        **ROUTE_ROWS,
        "MATCH (rp:RoutingProcess)-[h:HAS]->(b:BgpSession:Obj)": [
            *ROUTE_ROWS["MATCH (rp:RoutingProcess)-[h:HAS]->(b:BgpSession:Obj)"],
            {
                "uid": "bgp:b:1",
                "peer_ip": "192.168.2.35",
                "peer_asn": 65010,
                "local_asn": 65020,
                "process_uid": "rp:b",
                "context_uid": "vrf:b:default",
            },
        ],
    }
    _install(monkeypatch, rows)
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}]
    )
    routing = body["routing_consequence"]
    assert sorted(s["uid"] for s in routing["bgp_sessions_to_a_denied_address"]) == ["bgp:a:1", "bgp:b:1"]
    assert sorted({s["context_uid"] for s in routing["bgp_sessions_to_a_denied_address"]}) == [
        "vrf:a:default",
        "vrf:b:default",
    ]
    assert routing["implied_intents"] == []


def test_a_change_that_denies_no_recorded_peer_or_next_hop_says_nothing_about_routing(monkeypatch):
    _install(monkeypatch, ROUTE_ROWS)
    _fake_trace(monkeypatch)
    _install_route_engine(monkeypatch)
    elsewhere = {
        "kind": "fw_rule.add",
        "params": {
            "rulebase": "fw:LAN",
            "position": 10,
            "action": "drop",
            "source": "any",
            "destination": "198.51.100.7",
        },
    }
    body = fw_overlay_read.simulate_change(
        object(), intents=[elsewhere], flows=[{"src": "10.0.0.5", "dst": "198.51.100.7"}]
    )
    assert "routing_consequence" not in body


def test_the_overlay_sessions_own_reads_do_not_re_enter_the_hook(monkeypatch):
    """A zone move resolves the interface's zone and the new pair through the same session."""
    _install(
        monkeypatch,
        {"MATCH (:Interface:Obj {uid: $iface, collection_ts: $snap})": [{"uid": "zone:lan", "name": "LAN"}]},
    )

    class _Recording:
        def rewrite(self, query: str, params: Any, rows: Any) -> Any:
            raise AssertionError("the hook ran for a supplementary read")

        zone_of = None
        pair_rows = None

    session = fw_overlay_read.OverlaySession(object(), _Recording())  # type: ignore[arg-type]
    assert session._zone_of("if:eth0") == "zone:lan"


# --- the next-hop withdrawal -----------------------------------------------
#
# The graph of every test below holds no `BgpSession` node for the next hop.

VYOS_VRF = "vrf:dev:x:vyos:core1:default"

# 192.168.2.35 and 192.168.2.36 are the only two recorded next hops for
# 10.10.10.1/32; 10.20.0.0/16 keeps a third next hop the change does not touch.
NEXT_HOP_ROWS = [
    {
        "kind": "LEARNED_ROUTE",
        "prefix": "10.10.10.1/32",
        "next_hop": "192.168.2.35",
        "protocol": "bgp",
        "interface": "eth0",
        "metric": 20,
        "context_uid": VYOS_VRF,
    },
    {
        "kind": "LEARNED_ROUTE",
        "prefix": "10.10.10.1/32",
        "next_hop": "192.168.2.36",
        "protocol": "bgp",
        "interface": "eth1",
        "metric": 20,
        "context_uid": VYOS_VRF,
    },
    {
        "kind": "LEARNED_ROUTE",
        "prefix": "10.20.0.0/16",
        "next_hop": "192.168.2.35",
        "protocol": "bgp",
        "interface": "eth0",
        "metric": 20,
        "context_uid": VYOS_VRF,
    },
    {
        "kind": "LEARNED_ROUTE",
        "prefix": "10.20.0.0/16",
        "next_hop": "10.9.9.9",
        "protocol": "ospf",
        "interface": "eth2",
        "metric": 110,
        "context_uid": VYOS_VRF,
    },
]

NO_BGP_ROWS: dict[str, Any] = {
    **CATALOG_ROWS,
    "MATCH (rp:RoutingProcess)-[h:HAS]->(b:BgpSession:Obj)": [],
    "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": NEXT_HOP_ROWS,
}


def _prefix(routing: dict[str, Any], context_uid: str, cidr: str) -> dict[str, Any]:
    vrf = next(v for v in routing["next_hop_withdrawal"]["vrfs"] if v["context_uid"] == context_uid)
    return next(p for p in vrf["prefixes"] if p["prefix"] == cidr)


def test_a_prefix_whose_every_recorded_next_hop_is_denied_loses_them_all(monkeypatch):
    """The case the graph holds: two next hops, both denied, no BgpSession node
    for either. The withdrawal is computed from the route edges alone."""
    _install(monkeypatch, NO_BGP_ROWS)
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}]
    )
    routing = body["routing_consequence"]
    assert routing["bgp_sessions_to_a_denied_address"] == []

    gone = _prefix(routing, VYOS_VRF, "10.10.10.1/32")
    assert [n["next_hop"] for n in gone["next_hops_before"]] == ["192.168.2.35", "192.168.2.36"]
    assert gone["next_hops_after"] == []
    assert gone["no_next_hop_left"] is True
    assert routing["next_hop_withdrawal"]["prefixes_with_no_next_hop_left"] == 1


def test_a_prefix_that_keeps_a_next_hop_is_reported_as_keeping_it(monkeypatch):
    _install(monkeypatch, NO_BGP_ROWS)
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "10.20.0.1"}]
    )
    kept = _prefix(body["routing_consequence"], VYOS_VRF, "10.20.0.0/16")
    assert [n["next_hop"] for n in kept["next_hops_before"]] == ["192.168.2.35", "10.9.9.9"]
    assert [n["next_hop"] for n in kept["next_hops_after"]] == ["10.9.9.9"]
    assert kept["no_next_hop_left"] is False


def test_the_protocol_property_does_not_decide_whether_a_next_hop_is_withdrawn(monkeypatch):
    """An OSPF route and a static route through a denied address are withdrawn on
    the same footing as a BGP one: the dependency is the next hop, not the
    protocol that recorded it."""
    rows = [
        {**NEXT_HOP_ROWS[0], "prefix": "198.51.100.0/24", "protocol": "ospf"},
        {**NEXT_HOP_ROWS[0], "prefix": "203.0.113.0/24", "kind": "STATIC_ROUTE", "protocol": None},
    ]
    _install(
        monkeypatch,
        {**NO_BGP_ROWS, "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": rows},
    )
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "198.51.100.7"}]
    )
    routing = body["routing_consequence"]
    assert _prefix(routing, VYOS_VRF, "198.51.100.0/24")["no_next_hop_left"] is True
    assert _prefix(routing, VYOS_VRF, "203.0.113.0/24")["no_next_hop_left"] is True


DENY_FROM = {
    "kind": "fw_rule.add",
    "params": {
        "rulebase": "fw:LAN",
        "position": 10,
        "action": "drop",
        "source": "192.168.2.35",
        "destination": "any",
    },
}


def test_a_source_side_deny_withdraws_a_learned_route_and_keeps_a_static_one(monkeypatch):
    rows = [
        NEXT_HOP_ROWS[0],
        {**NEXT_HOP_ROWS[0], "prefix": "203.0.113.0/24", "kind": "STATIC_ROUTE", "protocol": None},
    ]
    _install(
        monkeypatch,
        {**NO_BGP_ROWS, "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": rows},
    )
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY_FROM], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}]
    )
    routing = body["routing_consequence"]
    assert routing["denied_addresses"] == {"traffic_to": [], "traffic_from": ["192.168.2.35"]}
    assert _prefix(routing, VYOS_VRF, "10.10.10.1/32")["no_next_hop_left"] is True
    withdrawn = [p["prefix"] for v in routing["next_hop_withdrawal"]["vrfs"] for p in v["prefixes"]]
    assert withdrawn == ["10.10.10.1/32"]
    assert [r["prefix"] for r in routing["static_routes_kept_under_a_source_side_deny"]] == ["203.0.113.0/24"]


def test_a_denial_of_any_address_withdraws_no_next_hop(monkeypatch):
    _install(monkeypatch, NO_BGP_ROWS)
    _fake_trace(monkeypatch)
    intent = {
        "kind": "fw_rule.add",
        "params": {
            "rulebase": "fw:LAN",
            "position": 10,
            "action": "drop",
            "source": "any",
            "destination": "any",
        },
    }
    body = fw_overlay_read.simulate_change(
        object(), intents=[intent], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}]
    )
    assert "routing_consequence" not in body


# --- the next-hop withdrawal, merged with the RIB side store --------------------------


# _VRF_SITES does not hold this fragment.
_VRF_DEVICES_FRAGMENT = "RETURN DISTINCT v.uid AS context_uid, v.name AS vrf_name, d.uid AS device_uid"

SIDE_STORE_DEVICE = "dev:x:vyos:core1"


def _fake_rib(rows_by_device: dict[str, list[dict[str, Any]]]) -> Any:
    """The fake ignores context_uid and legacy_vrf."""

    class _Rib:
        def routes(
            self, device_uid: str, context_uid: str | None, *, legacy_vrf: str | None = None
        ) -> list[dict[str, Any]]:
            return list(rows_by_device.get(device_uid, ()))

    return _Rib()


def test_a_side_store_only_route_is_withdrawn_by_a_matching_deny(monkeypatch):
    """A Cisco device's routes are not in the graph."""
    _install(
        monkeypatch,
        {
            **NO_BGP_ROWS,
            "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": [],
            _VRF_DEVICES_FRAGMENT: [
                {"context_uid": VYOS_VRF, "vrf_name": "default", "device_uid": SIDE_STORE_DEVICE}
            ],
        },
    )
    _fake_trace(monkeypatch)
    rib = _fake_rib(
        {
            SIDE_STORE_DEVICE: [
                {
                    "prefix": "10.10.10.1/32",
                    "next_hop": "192.168.2.35",
                    "protocol": "bgp",
                    "interface": "eth0",
                    "metric": 20,
                }
            ]
        }
    )
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}], rib=rib
    )
    gone = _prefix(body["routing_consequence"], VYOS_VRF, "10.10.10.1/32")
    assert [n["next_hop"] for n in gone["next_hops_before"]] == ["192.168.2.35"]
    assert gone["next_hops_after"] == []
    assert gone["no_next_hop_left"] is True


def test_a_route_recorded_in_both_the_graph_and_the_side_store_counts_once(monkeypatch):
    _install(
        monkeypatch,
        {
            **NO_BGP_ROWS,
            _VRF_DEVICES_FRAGMENT: [
                {"context_uid": VYOS_VRF, "vrf_name": "default", "device_uid": SIDE_STORE_DEVICE}
            ],
        },
    )
    _fake_trace(monkeypatch)
    rib = _fake_rib(
        {
            SIDE_STORE_DEVICE: [
                {
                    "prefix": "10.10.10.1/32",
                    "next_hop": "192.168.2.35",
                    "protocol": "bgp",
                    "interface": "eth0",
                    "metric": 20,
                }
            ]
        }
    )
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}], rib=rib
    )
    gone = _prefix(body["routing_consequence"], VYOS_VRF, "10.10.10.1/32")
    # the side store's duplicate of the graph's own row adds no third entry
    assert [n["next_hop"] for n in gone["next_hops_before"]] == ["192.168.2.35", "192.168.2.36"]


def test_identical_routes_in_two_vrfs_are_two_rows(monkeypatch):
    """The dedupe key is per routing context."""
    other_vrf = "vrf:dev:x:vyos:core1:blue"
    _install(
        monkeypatch,
        {
            **NO_BGP_ROWS,
            "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": [],
            _VRF_DEVICES_FRAGMENT: [
                {"context_uid": VYOS_VRF, "vrf_name": "default", "device_uid": SIDE_STORE_DEVICE},
                {"context_uid": other_vrf, "vrf_name": "blue", "device_uid": SIDE_STORE_DEVICE},
            ],
        },
    )
    _fake_trace(monkeypatch)
    rib = _fake_rib(
        {
            SIDE_STORE_DEVICE: [
                {
                    "prefix": "10.10.10.1/32",
                    "next_hop": "192.168.2.35",
                    "protocol": "bgp",
                    "interface": "eth0",
                    "metric": 20,
                }
            ]
        }
    )
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}], rib=rib
    )
    routing = body["routing_consequence"]
    assert {v["context_uid"] for v in routing["next_hop_withdrawal"]["vrfs"]} == {VYOS_VRF, other_vrf}
    for context_uid in (VYOS_VRF, other_vrf):
        gone = _prefix(routing, context_uid, "10.10.10.1/32")
        assert [n["next_hop"] for n in gone["next_hops_before"]] == ["192.168.2.35"]
        assert gone["no_next_hop_left"] is True


def test_a_side_store_static_route_is_kept_under_a_source_side_deny(monkeypatch):
    """The side store has no `kind` column."""
    _install(
        monkeypatch,
        {
            **NO_BGP_ROWS,
            "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": [],
            _VRF_DEVICES_FRAGMENT: [
                {"context_uid": VYOS_VRF, "vrf_name": "default", "device_uid": SIDE_STORE_DEVICE}
            ],
        },
    )
    _fake_trace(monkeypatch)
    rib = _fake_rib(
        {
            SIDE_STORE_DEVICE: [
                {
                    "prefix": "10.10.10.1/32",
                    "next_hop": "192.168.2.35",
                    "protocol": "bgp",
                    "interface": "eth0",
                    "metric": 20,
                },
                {
                    "prefix": "203.0.113.0/24",
                    "next_hop": "192.168.2.35",
                    "protocol": "static",
                    "interface": "eth0",
                    "metric": 1,
                },
            ]
        }
    )
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY_FROM], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}], rib=rib
    )
    routing = body["routing_consequence"]
    assert _prefix(routing, VYOS_VRF, "10.10.10.1/32")["no_next_hop_left"] is True
    assert [r["prefix"] for r in routing["static_routes_kept_under_a_source_side_deny"]] == ["203.0.113.0/24"]


def test_no_rib_argument_reproduces_the_graph_only_withdrawal(monkeypatch):
    """`rib` defaults to None."""
    _install(monkeypatch, NO_BGP_ROWS)
    _fake_trace(monkeypatch)
    without_rib = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}]
    )
    _fake_trace(monkeypatch)
    with_explicit_none = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}], rib=None
    )
    assert with_explicit_none["routing_consequence"] == without_rib["routing_consequence"]


# --- flow selection --------------------------------------------------------


def test_flows_are_derived_from_the_change_set_when_none_are_supplied(monkeypatch):
    """An address denied as a destination is the destination, with traffic
    coming from the outside."""
    _install(monkeypatch, NO_BGP_ROWS)
    traced: list[tuple[str, str]] = []

    def trace(
        session: Any,
        src: str,
        dst: str,
        port: Any = None,
        proto: str = "tcp",
        rib: Any = None,
        gateways: Any = None,
    ) -> dict[str, Any]:
        traced.append((src, dst))
        return {"verdict": "permitted", "indeterminate": False, "warnings": [], "legs": [], "hops": []}

    monkeypatch.setattr(pathmod, "trace", trace)
    body = fw_overlay_read.simulate_change(object(), intents=[DENY], flows=[])

    # each flow is traced twice, so the distinct pairs are what was chosen
    assert sorted(set(traced)) == [("0.0.0.0/0", "192.168.2.35"), ("0.0.0.0/0", "192.168.2.36")]
    assert body["flow_count"] == 2
    assert "flows_derived" in body


def test_a_flow_that_crosses_no_changed_device_is_a_named_model_error(monkeypatch):
    _install(
        monkeypatch,
        {
            **NO_BGP_ROWS,
            "MATCH (d:Device)-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})": [
                {"uid": "dev:core1"}
            ],
        },
    )

    def trace(
        session: Any,
        src: str,
        dst: str,
        port: Any = None,
        proto: str = "tcp",
        rib: Any = None,
        gateways: Any = None,
    ) -> dict[str, Any]:
        return {
            "verdict": "permitted",
            "indeterminate": False,
            "warnings": [],
            "legs": [],
            "hops": [{"uid": "dev:access1", "kind": "Device", "label": "access1"}],
        }

    monkeypatch.setattr(pathmod, "trace", trace)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "192.168.2.10", "dst": "192.168.2.35"}]
    )
    flow = body["flows"][0]
    assert body["changed_devices"] == ["dev:core1"]
    assert flow["crosses_a_changed_device"] is False
    assert flow["model_error"]["kind"] == "flow-does-not-cross-the-changed-device"
    assert any(e["kind"] == "flow-does-not-cross-the-changed-device" for e in body["model_errors"])


def test_a_flow_that_crosses_the_changed_device_carries_no_such_error(monkeypatch):
    _install(
        monkeypatch,
        {
            **NO_BGP_ROWS,
            "MATCH (d:Device)-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})": [
                {"uid": "dev:core1"}
            ],
        },
    )

    def trace(
        session: Any,
        src: str,
        dst: str,
        port: Any = None,
        proto: str = "tcp",
        rib: Any = None,
        gateways: Any = None,
    ) -> dict[str, Any]:
        return {
            "verdict": "permitted",
            "indeterminate": False,
            "warnings": [],
            "legs": [],
            "hops": [{"uid": "dev:core1", "kind": "Device", "label": "core1"}],
        }

    monkeypatch.setattr(pathmod, "trace", trace)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}]
    )
    assert body["flows"][0]["crosses_a_changed_device"] is True
    assert "model_error" not in body["flows"][0]


def test_the_bgp_engine_is_not_consulted_beside_the_withdrawal(monkeypatch):
    """The route engine is not called from an address dependency alone."""
    rows = {
        **ROUTE_ROWS,
        "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": [
            {
                "kind": "LEARNED_ROUTE",
                "prefix": "203.0.113.0/24",
                "next_hop": "192.168.2.35",
                "protocol": "bgp",
                "interface": "eth0",
                "metric": 20,
                "context_uid": "vrf:a:default",
            }
        ],
    }
    _install(monkeypatch, rows)
    _fake_trace(monkeypatch)

    engine_calls: list[str] = []

    def read_input(session: Any, **kw: Any) -> simul_read.GraphInput:
        engine_calls.append("read_simulation_input")
        return simul_read.GraphInput(
            processes=[{"uid": "rp:a", "context_uid": "vrf:a:default"}],
            sessions=[{"uid": "bgp:a:1"}, {"uid": "bgp:a:2"}],
        )

    def compute(*, processes, sessions, policies, local_routes, platform) -> RouteDelta:
        engine_calls.append("compute_route_delta")
        return RouteDelta(rib=[], model_errors=[])

    monkeypatch.setattr(simul_read, "read_simulation_input", read_input)
    monkeypatch.setattr(provider, "compute_route_delta", compute)

    routing = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "203.0.113.7"}]
    )["routing_consequence"]

    assert engine_calls == []
    assert _prefix(routing, "vrf:a:default", "203.0.113.0/24")["no_next_hop_left"] is True
    assert routing["implied_intents"] == []
    assert routing["predicted_prefixes_withdrawn"] == []
    assert routing["predicted_rows_changed"] == []
    assert routing["predicted_changed_count"] == 0
    assert routing["scopes_predicted"] == []


# --- which device a changed rulebase sits on ------------------------------


def test_a_changed_rulebase_is_resolved_through_every_binding_the_schema_defines(monkeypatch):
    """`vyos.py` writes ENFORCES for filter chains alone."""
    graph = _install(
        monkeypatch,
        {**NO_BGP_ROWS, "-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})": []},
    )
    _fake_trace(monkeypatch)
    fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}]
    )
    asked = [q for q, params in graph.calls if params.get("rb") == "fw:LAN"]
    assert asked, "the rulebase's devices were never read"
    query = asked[0]
    # the device that enforces it, directly or as a cluster member or a VDOM
    assert "MATCH (d:Device)-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})" in query
    assert "(g:RedundancyGroup)-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})" in query
    assert "MATCH (v:VrfInstance)-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})" in query
    # the zone pair a rulebase acts at, and the zones its own rules match on
    assert (
        "(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})\n"
        "      -[z:FROM_ZONE|TO_ZONE]->(zn:Zone)-[c:CONTAINS]->" in query
    )
    assert "-[hr:HAS_RULE]->(r:FwRule)-[z:FROM_ZONE|TO_ZONE]->(zn:Zone)" in query
    # the object-attached cloud binding, and the layer another rulebase jumps to
    assert "MATCH (x)-[p:PROTECTED_BY]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})" in query
    assert "-[j:JUMPS_TO]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})" in query


def test_a_zone_pair_rulebase_resolves_to_the_device_its_zones_interfaces_are_on(monkeypatch):
    """The row the zone path returns is a device like any other: it lands in
    changed_devices, it decides whether a flow crosses the change, and no model
    error is raised for a rulebase nothing ENFORCES."""
    _install(
        monkeypatch,
        {
            **NO_BGP_ROWS,
            "-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})": [
                {"uid": "dev:x:vyos:core1"}
            ],
        },
    )

    def trace(
        session: Any,
        src: str,
        dst: str,
        port: Any = None,
        proto: str = "tcp",
        rib: Any = None,
        gateways: Any = None,
    ) -> dict[str, Any]:
        return {
            "verdict": "permitted",
            "indeterminate": False,
            "warnings": [],
            "legs": [],
            "hops": [{"uid": "dev:x:vyos:core1", "kind": "Device", "label": "core1"}],
        }

    monkeypatch.setattr(pathmod, "trace", trace)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}]
    )
    assert body["changed_devices"] == ["dev:x:vyos:core1"]
    assert body["flows"][0]["crosses_a_changed_device"] is True
    assert not [e for e in body["model_errors"] if "rulebase" in e["kind"]]


def test_only_a_rulebase_no_binding_resolves_is_reported_and_the_wording_names_that(monkeypatch):
    """The error stands only when every binding came back empty."""
    _install(
        monkeypatch,
        {**NO_BGP_ROWS, "-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})": []},
    )
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}]
    )
    gap = next(e for e in body["model_errors"] if e["kind"] == "changed-rulebase-has-no-enforcement-point")
    assert gap["subject"] == "fw:LAN"
    assert "no recorded enforcement point" in gap["detail"]
    assert "no Device ENFORCES" not in gap["detail"]
    assert body["changed_devices"] == []
    assert body["flows"][0]["crosses_a_changed_device"] is None


# --- the routing-consequence-not-evaluated caveat --------------------------


def test_a_remove_only_change_set_carries_the_not_evaluated_caveat_and_no_routing_key(monkeypatch):
    """`denied_directions()` reads only `fw_rule.add` deny intents."""
    _install(monkeypatch, CATALOG_ROWS)
    body = fw_overlay_read.simulate_change(
        object(),
        intents=[{"kind": "fw_rule.remove", "params": {"rulebase": "fw:LAN", "rule": "fw:rule:1"}}],
    )
    caveat = next(e for e in body["model_errors"] if e["kind"] == "routing-consequence-not-evaluated")
    assert "fw_rule.remove" in caveat["detail"]
    assert "routing_consequence" not in body


def test_an_add_deny_change_set_computes_the_routing_follow_on_with_no_caveat(monkeypatch):
    _install(monkeypatch, NO_BGP_ROWS)
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}]
    )
    assert "routing_consequence" in body
    assert not any(e["kind"] == "routing-consequence-not-evaluated" for e in body["model_errors"])


def test_an_add_permit_only_change_set_reports_no_caveat_and_no_routing_key(monkeypatch):
    """The gap the caveat names is `fw_rule.remove`/`modify`, NAT and zone intents."""
    _install(monkeypatch, CATALOG_ROWS)
    body = fw_overlay_read.simulate_change(
        object(),
        intents=[
            {
                "kind": "fw_rule.add",
                "params": {
                    "rulebase": "fw:LAN",
                    "position": 10,
                    "action": "permit",
                    "source": "any",
                    "destination": "any",
                },
            }
        ],
    )
    assert not any(e["kind"] == "routing-consequence-not-evaluated" for e in body["model_errors"])
    assert "routing_consequence" not in body


# --- deriving the rulebase from the device an intent names ----------------

# The device-addressed change set: two hosts on a bridge domain, blocked as a
# source on the router that serves them, with no rulebase named anywhere.
DENY_ON_DEVICE: dict[str, Any] = {
    "kind": "fw_rule.add",
    "params": {
        "device": "dev:core1",
        "position": 10,
        "action": "drop",
        "source": ["192.168.2.35", "192.168.2.36"],
        "destination": "any",
    },
}

# What the device's own bindings say, in the shape `_DEVICE_RULEBASES` returns.
# eth1 serves the two hosts; eth0 serves a different subnet.
DEVICE_BINDING_ROWS: list[dict[str, Any]] = [
    {
        "rb_uid": "fw:LAN-to-WAN",
        "rb_name": "LAN to WAN",
        "binding": "a zone pair binds it to an interface on the device",
        "side": "FROM_ZONE",
        "iface": "if:eth1",
    },
    {
        "rb_uid": "fw:WAN-to-LAN",
        "rb_name": "WAN to LAN",
        "binding": "a zone pair binds it to an interface on the device",
        "side": "TO_ZONE",
        "iface": "if:eth1",
    },
    {
        "rb_uid": "fw:MGMT-to-WAN",
        "rb_name": "MGMT to WAN",
        "binding": "a zone pair binds it to an interface on the device",
        "side": "FROM_ZONE",
        "iface": "if:eth0",
    },
]

DEVICE_SERVED_ROWS: list[dict[str, Any]] = [
    {
        "uid": "if:eth0",
        "name": "eth0",
        "prefixes": ["10.0.0.0/24"],
        "bridge_domain_ips": [],
        "attached_ips": [],
    },
    {
        "uid": "if:eth1",
        "name": "eth1",
        "prefixes": ["192.168.2.0/24"],
        "bridge_domain_ips": ["192.168.2.35", "192.168.2.36"],
        "attached_ips": [],
    },
]

_Q_BINDINGS = "MATCH (d:Device:Obj {uid: $dev, collection_ts: $snap})-[e:ENFORCES]->(rb:FwRulebase)"

DERIVE_ROWS: dict[str, Any] = {
    _Q_BINDINGS: DEVICE_BINDING_ROWS,
    "collect(DISTINCT p.cidr) AS prefixes": DEVICE_SERVED_ROWS,
    "-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})": [{"uid": "dev:core1"}],
    **NO_BGP_ROWS,
}


def test_a_source_side_deny_on_a_device_derives_the_rulebase_holding_that_side(monkeypatch):
    """The rulebases with the zone of eth1 on the source side are the candidates."""
    _install(monkeypatch, DERIVE_ROWS)
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY_ON_DEVICE], flows=[{"src": "192.168.2.35", "dst": "8.8.8.8"}]
    )
    derived = body["rulebases_derived"][0]
    assert [r["uid"] for r in derived["rulebases"]] == ["fw:LAN-to-WAN"]
    assert derived["device"] == "dev:core1"
    assert [i["params"]["rulebase"] for i in body["intents"]] == ["fw:LAN-to-WAN"]


def test_the_derivation_says_which_rulebases_it_chose_and_what_it_chose_them_from(monkeypatch):
    _install(monkeypatch, DERIVE_ROWS)
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY_ON_DEVICE], flows=[{"src": "192.168.2.35", "dst": "8.8.8.8"}]
    )
    derived = body["rulebases_derived"][0]
    bound = derived["rulebases"][0]["bound_by"][0]
    assert bound["side"] == "source"
    assert bound["interface"] == "if:eth1"
    assert "zone pair" in bound["binding"]
    served = derived["interfaces_serving_the_stated_addresses"]["source"]
    assert [i["uid"] for i in served] == ["if:eth1"]
    # both recorded ways the interface serves them: its own connected prefix,
    # and the endpoints on the bridge domain its VLAN realizes
    assert served[0]["serves"] == ["192.168.2.0/24", "192.168.2.35", "192.168.2.36"]
    assert derived["rulebases_bound_to_the_device"] == [
        "fw:LAN-to-WAN",
        "fw:MGMT-to-WAN",
        "fw:WAN-to-LAN",
    ]
    assert "192.168.2.35" in derived["basis"]
    assert "rulebases_derived" in body["rulebase_derivation"]


def test_a_device_with_two_candidate_rulebases_uses_them_both(monkeypatch):
    second = {
        "rb_uid": "fw:LAN-to-DMZ",
        "rb_name": "LAN to DMZ",
        "binding": "a zone pair binds it to an interface on the device",
        "side": "FROM_ZONE",
        "iface": "if:eth1",
    }
    _install(monkeypatch, {**DERIVE_ROWS, _Q_BINDINGS: [*DEVICE_BINDING_ROWS, second]})
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY_ON_DEVICE], flows=[{"src": "192.168.2.35", "dst": "8.8.8.8"}]
    )
    assert [r["uid"] for r in body["rulebases_derived"][0]["rulebases"]] == [
        "fw:LAN-to-DMZ",
        "fw:LAN-to-WAN",
    ]
    assert [i["params"]["rulebase"] for i in body["intents"]] == ["fw:LAN-to-DMZ", "fw:LAN-to-WAN"]


def test_a_destination_side_deny_derives_the_rulebase_holding_the_destination_side(monkeypatch):
    _install(monkeypatch, DERIVE_ROWS)
    _fake_trace(monkeypatch)
    inbound = {
        "kind": "fw_rule.add",
        "params": {
            "device": "dev:core1",
            "position": 10,
            "action": "drop",
            "source": "any",
            "destination": ["192.168.2.35", "192.168.2.36"],
        },
    }
    body = fw_overlay_read.simulate_change(
        object(), intents=[inbound], flows=[{"src": "8.8.8.8", "dst": "192.168.2.35"}]
    )
    assert [r["uid"] for r in body["rulebases_derived"][0]["rulebases"]] == ["fw:WAN-to-LAN"]


def test_a_binding_that_names_no_zone_or_no_interface_governs_the_traffic_either_way(monkeypatch):
    """A device-wide rulebase is not narrowed by an interface it never names,
    and a VDOM's rulebase is narrowed by the interfaces that VDOM holds."""
    rows = [
        {
            "rb_uid": "fw:filter",
            "rb_name": "filter",
            "binding": "the device ENFORCES it",
            "side": None,
            "iface": None,
        },
        {
            "rb_uid": "fw:vdom-a",
            "rb_name": "vdom a",
            "binding": "a VrfInstance on the device ENFORCES it",
            "side": None,
            "iface": "if:eth1",
        },
        {
            "rb_uid": "fw:vdom-b",
            "rb_name": "vdom b",
            "binding": "a VrfInstance on the device ENFORCES it",
            "side": None,
            "iface": "if:eth0",
        },
    ]
    _install(monkeypatch, {**DERIVE_ROWS, _Q_BINDINGS: rows})
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY_ON_DEVICE], flows=[{"src": "192.168.2.35", "dst": "8.8.8.8"}]
    )
    assert [r["uid"] for r in body["rulebases_derived"][0]["rulebases"]] == ["fw:filter", "fw:vdom-a"]


def test_addresses_no_interface_on_the_device_serves_narrow_nothing(monkeypatch):
    """An address reached over a route is not behind an interface."""
    _install(monkeypatch, DERIVE_ROWS)
    _fake_trace(monkeypatch)
    elsewhere = {
        "kind": "fw_rule.add",
        "params": {
            "device": "dev:core1",
            "position": 10,
            "action": "drop",
            "source": "198.51.100.7",
            "destination": "any",
        },
    }
    body = fw_overlay_read.simulate_change(
        object(), intents=[elsewhere], flows=[{"src": "198.51.100.7", "dst": "8.8.8.8"}]
    )
    derived = body["rulebases_derived"][0]
    assert [r["uid"] for r in derived["rulebases"]] == [
        "fw:LAN-to-WAN",
        "fw:MGMT-to-WAN",
        "fw:WAN-to-LAN",
    ]
    assert "nothing narrows them" in derived["basis"]


def test_a_device_the_snapshot_binds_no_rulebase_to_is_a_named_model_error(monkeypatch):
    _install(monkeypatch, {**DERIVE_ROWS, _Q_BINDINGS: []})
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY_ON_DEVICE], flows=[{"src": "192.168.2.35", "dst": "8.8.8.8"}]
    )
    gap = next(e for e in body["model_errors"] if e["kind"] == "rulebase-not-derivable-from-the-device")
    assert gap["subject"] == "dev:core1"
    assert "binds no rulebase to that device at all" in gap["detail"]
    assert body["intents"] == []
    assert body["rulebases_derived"][0]["rulebases"] == []


def test_a_device_whose_rulebases_hold_no_serving_interface_on_that_side_is_the_same_error(monkeypatch):
    """Bindings exist and none of them is on the denied side of the traffic. The
    error says so and names the candidates it rejected; no fallback is taken."""
    only_other_side = [DEVICE_BINDING_ROWS[1], DEVICE_BINDING_ROWS[2]]
    _install(monkeypatch, {**DERIVE_ROWS, _Q_BINDINGS: only_other_side})
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY_ON_DEVICE], flows=[{"src": "192.168.2.35", "dst": "8.8.8.8"}]
    )
    gap = next(e for e in body["model_errors"] if e["kind"] == "rulebase-not-derivable-from-the-device")
    assert "fw:WAN-to-LAN" in gap["detail"]
    assert "none of them holds an interface serving the stated addresses" in gap["detail"]
    assert body["intents"] == []


def test_an_intent_that_names_its_rulebase_derives_nothing_and_reads_no_device(monkeypatch):
    graph = _install(monkeypatch, DERIVE_ROWS)
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}]
    )
    assert "rulebases_derived" not in body
    assert "rulebase_derivation" not in body
    assert body["intents"] == [DENY]
    assert not [q for q, params in graph.calls if "dev" in params]


def test_a_rule_uid_belongs_to_one_rulebase_so_a_device_cannot_stand_in_for_it(monkeypatch):
    _install(monkeypatch, DERIVE_ROWS)
    _fake_trace(monkeypatch)
    with pytest.raises(ProposalError, match="cannot be derived from a device"):
        fw_overlay_read.simulate_change(
            object(),
            intents=[{"kind": "fw_rule.remove", "params": {"device": "dev:core1", "rule": "fw:rule:9"}}],
            flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}],
        )


def test_a_device_is_resolved_to_its_rulebases_through_every_binding_the_schema_defines(monkeypatch):
    """`_RULEBASE_DEVICES` walks seven binding chains; the inverse read walks the
    same seven."""
    graph = _install(monkeypatch, DERIVE_ROWS)
    _fake_trace(monkeypatch)
    fw_overlay_read.simulate_change(
        object(), intents=[DENY_ON_DEVICE], flows=[{"src": "192.168.2.35", "dst": "8.8.8.8"}]
    )
    query = next(q for q, params in graph.calls if params.get("dev") == "dev:core1" and "FwRulebase" in q)
    assert "MATCH (d:Device:Obj {uid: $dev, collection_ts: $snap})-[e:ENFORCES]->(rb:FwRulebase)" in query
    assert "-[m:MEMBER_OF]->(g:RedundancyGroup)-[e:ENFORCES]->(rb:FwRulebase)" in query
    assert "(i)-[iv:IN_VRF]->(v:VrfInstance)-[e:ENFORCES]->(rb:FwRulebase)" in query
    assert (
        "MATCH (rb:FwRulebase:Obj {collection_ts: $snap})-[z:FROM_ZONE|TO_ZONE]->(zn:Zone)-[c:CONTAINS]->"
        in query
    )
    assert "-[hr:HAS_RULE]->(r:FwRule)-[z:FROM_ZONE|TO_ZONE]->(zn:Zone)" in query
    assert "MATCH (x)-[p:PROTECTED_BY]->(rb:FwRulebase:Obj {collection_ts: $snap})" in query
    assert "-[j:JUMPS_TO]->(rb:FwRulebase)" in query
    # and the side of a zone-scoped binding comes back with it
    assert "type(z) AS side" in query


def test_an_address_is_matched_to_an_interface_by_prefix_bridge_domain_or_attachment(monkeypatch):
    graph = _install(monkeypatch, DERIVE_ROWS)
    _fake_trace(monkeypatch)
    fw_overlay_read.simulate_change(
        object(), intents=[DENY_ON_DEVICE], flows=[{"src": "192.168.2.35", "dst": "8.8.8.8"}]
    )
    query = next(q for q, params in graph.calls if params.get("dev") == "dev:core1" and "cidr" in q)
    assert "(i)-[hi:HAS_IP]->(ia:IpAddress)-[inp:IN]->(p:Prefix)" in query
    assert "(i)-[bt:BOUND_TO]->(vl:VlanInstance)-[rz:REALIZES]->(bd)<-[ein:IN]-(ep:Endpoint)" in query
    assert "(ae:Endpoint)-[at:ATTACHED]->(i)" in query
    assert "bd:BridgeDomain OR bd:L2Segment" in query


# --- the path rows behind a verdict ---------------------------------------


def _multi_path_trace(monkeypatch: pytest.MonkeyPatch) -> None:
    """A tracer that walks thirteen paths, seven of which the overlay blocks."""

    def trace(
        session: Any,
        src: str,
        dst: str,
        port: Any = None,
        proto: str = "tcp",
        rib: Any = None,
        gateways: Any = None,
    ) -> dict[str, Any]:
        overlaid = isinstance(session, fw_overlay_read.OverlaySession)
        legs = []
        for i in range(12):
            blocked = overlaid and i < 6
            legs.append(
                {
                    "cidr": f"10.{i}.0.0/16",
                    "egress": "eth0",
                    "next_hop": f"10.0.0.{i}",
                    "table": "main",
                    "blocked": blocked,
                    "firewall": "LAN policy (LAN>WAN) drop by rule 10" if blocked else None,
                    "fw_uid": "fw:LAN" if blocked else "fw:INTRA",
                }
            )
        # the second lane of an ECMP pair: same destination, other next hop
        legs.append({**legs[0], "next_hop": "10.0.0.99"})
        return {
            "verdict": "13 paths: " + ("7 of 13 blocked" if overlaid else "permitted"),
            "indeterminate": False,
            "warnings": [],
            "legs": legs,
            "hops": [],
        }

    monkeypatch.setattr(pathmod, "trace", trace)


def test_the_verdict_prose_is_kept_but_the_paths_are_carried_as_rows(monkeypatch):
    _install(monkeypatch, CATALOG_ROWS)
    _multi_path_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "0.0.0.0/0"}]
    )
    flow = body["flows"][0]
    assert flow["before"]["detail"].startswith("13 paths")

    paths = flow["paths"]
    assert paths["path_count_before"] == 13
    assert paths["path_count_after"] == 13
    assert paths["blocked_before"] == 0
    assert paths["blocked_after"] == 7
    assert paths["changed"] == 7
    # and the same counts, summed over the flows, on the answer itself
    assert body["path_count_after"] == 13
    assert body["paths_blocked_after"] == 7
    assert body["paths_changed"] == 7

    row = paths["groups"][0]
    assert row["path_count"] == 7
    assert row["after"]["blocked"] is True
    assert row["after"]["decided_by"] == "LAN policy (LAN>WAN) drop by rule 10"
    assert row["egress"] == "eth0"


def test_the_two_lanes_of_an_ecmp_pair_stay_distinguishable(monkeypatch):
    """`eth0 for 10.10.10.1` twice in the prose is two paths through two next
    hops; the rows carry the next hop that tells them apart."""
    _install(monkeypatch, CATALOG_ROWS)
    _multi_path_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "0.0.0.0/0"}]
    )
    blocked = body["flows"][0]["paths"]["groups"][0]
    # seven paths over six destinations: the pair to 10.0.0.0/16 is two rows'
    # worth of path, counted as two and reached through two next hops
    assert blocked["path_count"] == 7
    assert blocked["destination_count"] == 6
    assert blocked["next_hop_count"] == 7
    assert blocked["destinations"][0] == "10.0.0.0/16"


def test_a_path_the_change_does_not_govern_says_which_rulebase_decided_it(monkeypatch):
    _install(monkeypatch, CATALOG_ROWS)
    _multi_path_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "0.0.0.0/0"}]
    )
    survivors = [g for g in body["flows"][0]["paths"]["groups"] if not g["after"]["blocked"]]
    assert survivors
    assert survivors[0]["note"] == "decided by fw:INTRA, which this change does not alter"
    assert survivors[0]["changed"] is False


def test_the_derived_flows_are_a_bounded_set_that_says_what_it_left_out(monkeypatch):
    rows = [
        {
            "kind": "LEARNED_ROUTE",
            "prefix": f"10.{i}.0.0/16",
            "next_hop": "192.168.2.35",
            "protocol": "bgp",
            "context_uid": VYOS_VRF,
        }
        for i in range(30)
    ]
    _install(
        monkeypatch,
        {**NO_BGP_ROWS, "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": rows},
    )
    traced: list[tuple[str, str]] = []

    def trace(
        session: Any,
        src: str,
        dst: str,
        port: Any = None,
        proto: str = "tcp",
        rib: Any = None,
        gateways: Any = None,
    ) -> dict[str, Any]:
        traced.append((src, dst))
        return {"verdict": "permitted", "indeterminate": False, "warnings": [], "legs": [], "hops": []}

    monkeypatch.setattr(pathmod, "trace", trace)
    deny_from = {
        "kind": "fw_rule.add",
        "params": {**DENY["params"], "source": ["192.168.2.35", "192.168.2.36"], "destination": "any"},
    }
    body = fw_overlay_read.simulate_change(object(), intents=[deny_from], flows=[])

    assert body["flow_count"] == fw_overlay_read._MAX_DERIVED_FLOWS
    assert body["flows_derived_count"] == fw_overlay_read._MAX_DERIVED_FLOWS
    assert body["flows_derived_truncated"] is True
    assert body["flows_derived_not_traced"] > 0
    # the default route is traced for both denied addresses before any one
    # source's prefixes exhaust the cap
    assert ("192.168.2.35", "0.0.0.0/0") in traced
    assert ("192.168.2.36", "0.0.0.0/0") in traced


def test_the_routing_consequence_leads_with_one_sentence_of_counts(monkeypatch):
    _install(monkeypatch, NO_BGP_ROWS)
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}]
    )
    assert body["routing_consequence"]["headline"] == (
        "2 prefix(es) across 1 VRF(s) lose a recorded next hop, 1 of them every next hop the snapshot records"
    )


# --- how far the withdrawal is followed: depth ------------------------------
#
# The chain: 10.10.10.1/32 loses both its recorded next hops to the denial, so
# it is stranded at level 1. 172.16.0.0/16's only next hop is 10.10.10.1, which
# nothing but the stranded /32 covers, so it goes at level 2; 172.17.0.0/16's
# only next hop sits in 172.16.0.0/16, so it goes at level 3. 10.20.0.0/16's next
# hop is covered by no recorded prefix at all and is left alone at every level.

DEEP_ROWS = [
    NEXT_HOP_ROWS[0],
    NEXT_HOP_ROWS[1],
    {
        "kind": "LEARNED_ROUTE",
        "prefix": "172.16.0.0/16",
        "next_hop": "10.10.10.1",
        "protocol": "bgp",
        "interface": "eth0",
        "metric": 20,
        "context_uid": VYOS_VRF,
    },
    {
        "kind": "LEARNED_ROUTE",
        "prefix": "172.17.0.0/16",
        "next_hop": "172.16.0.9",
        "protocol": "bgp",
        "interface": "eth0",
        "metric": 20,
        "context_uid": VYOS_VRF,
    },
    {
        "kind": "LEARNED_ROUTE",
        "prefix": "10.20.0.0/16",
        "next_hop": "10.9.9.9",
        "protocol": "ospf",
        "interface": "eth2",
        "metric": 110,
        "context_uid": VYOS_VRF,
    },
]

DEEP_GRAPH: dict[str, Any] = {
    **NO_BGP_ROWS,
    "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": DEEP_ROWS,
}


def _simulate(monkeypatch, answers: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    _install(monkeypatch, answers)
    _fake_trace(monkeypatch)
    return fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}], **kwargs
    )


def _withdrawn_prefixes(routing: dict[str, Any]) -> list[str]:
    withdrawal = routing["next_hop_withdrawal"]
    return sorted(p["prefix"] for v in withdrawal["vrfs"] for p in v["prefixes"])


def test_omitting_depth_and_sites_follows_the_chain_one_level_and_says_so(monkeypatch):
    routing = _simulate(monkeypatch, DEEP_GRAPH)["routing_consequence"]
    assert _withdrawn_prefixes(routing) == ["10.10.10.1/32"]
    walk = routing["walk"]
    assert walk["depth_requested"] == 1
    assert walk["depth"] == 1
    assert walk["levels_walked"] == 1
    assert [lv["level"] for lv in walk["levels"]] == [1]
    # no site filter was asked for, so nothing about sites is in the answer
    assert "site_scope" not in routing


def test_a_second_level_withdrawal_follows_a_prefix_that_lost_every_next_hop(monkeypatch):
    """Level 2: a route whose next hop resolves only through a prefix that level 1
    left with no recorded next hop."""
    routing = _simulate(monkeypatch, DEEP_GRAPH, depth=2)["routing_consequence"]
    assert _withdrawn_prefixes(routing) == ["10.10.10.1/32", "172.16.0.0/16"]

    followed = _prefix(routing, VYOS_VRF, "172.16.0.0/16")
    assert followed["level"] == 2
    assert followed["no_next_hop_left"] is True
    assert followed["no_next_hop_left_at_level"] == 2
    assert followed["withdrawn_next_hops"][0]["withdrawn_because"] == (
        "this next hop resolves only through 10.10.10.1/32, which the change leaves with no recorded next hop"
    )
    # the prefix whose next hop no recorded prefix covers is untouched at every level
    assert "10.20.0.0/16" not in _withdrawn_prefixes(routing)


def test_each_level_carries_its_own_counts(monkeypatch):
    routing = _simulate(monkeypatch, DEEP_GRAPH, depth=3)["routing_consequence"]
    levels = routing["walk"]["levels"]
    assert [lv["level"] for lv in levels] == [1, 2, 3]
    assert [lv["prefix_count"] for lv in levels] == [1, 1, 1]
    assert [lv["prefixes_with_no_next_hop_left"] for lv in levels] == [1, 1, 1]
    assert [lv["withdrawn_route_edge_count"] for lv in levels] == [2, 1, 1]
    assert levels[1]["sample"] == ["172.16.0.0/16 in " + VYOS_VRF]
    assert levels[2]["sample"] == ["172.17.0.0/16 in " + VYOS_VRF]
    assert routing["headline"].endswith(
        "following the dependency chain 3 levels deep; the walk was stopped by the depth limit, "
        "so this is part of the consequence and not all of it"
    )


def test_a_next_hop_a_surviving_prefix_also_covers_is_not_withdrawn(monkeypatch):
    """Resolution falls back to the less specific route, so a next hop is only
    unusable when every recorded prefix covering it is stranded."""
    rows = [
        NEXT_HOP_ROWS[0],
        NEXT_HOP_ROWS[1],
        {**DEEP_ROWS[4], "prefix": "10.10.0.0/16", "next_hop": "10.9.9.9"},
        {**DEEP_ROWS[2], "prefix": "192.0.2.0/24", "next_hop": "10.10.10.1"},
    ]
    routing = _simulate(
        monkeypatch,
        {**NO_BGP_ROWS, "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": rows},
        depth=4,
    )["routing_consequence"]
    # 10.10.0.0/16 still holds a next hop and still covers 10.10.10.1
    assert _withdrawn_prefixes(routing) == ["10.10.10.1/32"]
    assert routing["walk"]["complete"] is True


def test_a_depth_above_the_cap_runs_at_the_cap_and_says_it_did(monkeypatch):
    routing = _simulate(monkeypatch, DEEP_GRAPH, depth=99)["routing_consequence"]
    walk = routing["walk"]
    assert walk["depth_requested"] == 99
    assert walk["depth"] == fw_overlay_read._MAX_WITHDRAWAL_DEPTH == 8
    assert walk["depth_cap"] == 8
    assert walk["depth_clamped"] is True
    # the chain here is three levels long, so the cap is not what ended the walk
    assert walk["levels_walked"] == 3
    assert walk["complete"] is True


def test_a_depth_below_one_is_refused(monkeypatch):
    _install(monkeypatch, DEEP_GRAPH)
    _fake_trace(monkeypatch)
    with pytest.raises(ProposalError):
        fw_overlay_read.simulate_change(
            object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "10.10.10.1"}], depth=0
        )


# 172.16.0.0/16 and 172.17.0.0/16 each keep a next hop inside the other.
CYCLE_ROWS = [
    NEXT_HOP_ROWS[0],
    NEXT_HOP_ROWS[1],
    {**DEEP_ROWS[2], "prefix": "172.16.0.0/16", "next_hop": "10.10.10.1"},
    {**DEEP_ROWS[2], "prefix": "172.16.0.0/16", "next_hop": "172.17.0.9"},
    {**DEEP_ROWS[2], "prefix": "172.17.0.0/16", "next_hop": "172.16.0.9"},
    # a recursive entry: its own next hop sits inside the prefix it is a route to
    {**DEEP_ROWS[2], "prefix": "10.50.0.0/16", "next_hop": "10.50.0.9"},
]


def test_a_dependency_cycle_ends_the_walk(monkeypatch):
    """The walk terminates on a cycle, below the cap."""
    routing = _simulate(
        monkeypatch,
        {**NO_BGP_ROWS, "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": CYCLE_ROWS},
        depth=8,
    )["routing_consequence"]
    walk = routing["walk"]
    assert walk["levels_walked"] == 2
    assert walk["level_count"] == 2
    assert walk["complete"] is True
    assert walk["limits"] == []
    # the mutually dependent pair each keep a next hop, so neither strands the other
    assert _prefix(routing, VYOS_VRF, "172.16.0.0/16")["no_next_hop_left"] is False
    assert [n["next_hop"] for n in _prefix(routing, VYOS_VRF, "172.16.0.0/16")["next_hops_after"]] == [
        "172.17.0.9"
    ]
    assert "172.17.0.0/16" not in _withdrawn_prefixes(routing)
    # a route whose next hop sits inside its own prefix does not strand itself
    assert "10.50.0.0/16" not in _withdrawn_prefixes(routing)


# --- where the withdrawal is followed: the site filter ----------------------

DC_VRF = "vrf:dev:x:vyos:dc1:default"
UNSITED_VRF = "vrf:dev:x:vyos:lab1:default"

TWO_SITE_ROWS = [
    NEXT_HOP_ROWS[0],
    NEXT_HOP_ROWS[1],
    {**DEEP_ROWS[2], "prefix": "172.16.0.0/16", "next_hop": "10.10.10.1"},
    {**NEXT_HOP_ROWS[0], "prefix": "10.30.0.0/16", "context_uid": DC_VRF},
    {**NEXT_HOP_ROWS[0], "prefix": "10.31.0.0/16", "context_uid": DC_VRF},
    {**NEXT_HOP_ROWS[0], "prefix": "10.40.0.0/16", "context_uid": UNSITED_VRF},
]

SITE_GRAPH: dict[str, Any] = {
    **NO_BGP_ROWS,
    "MATCH (v:VrfInstance:Obj)-[r:LEARNED_ROUTE|STATIC_ROUTE]->(p:Prefix)": TWO_SITE_ROWS,
    "MATCH (s:Site:Obj)": [
        {"uid": "site:hq", "code": "HQ", "name": "Head office"},
        {"uid": "site:dc1", "code": "DC1", "name": "Data centre 1"},
    ],
    "MATCH (v:VrfInstance:Obj)<-[iv:IN_VRF]-": [
        {"context_uid": VYOS_VRF, "site_uids": ["site:hq"]},
        {"context_uid": DC_VRF, "site_uids": ["site:dc1"]},
    ],
}


def test_omitting_the_site_filter_walks_the_whole_estate(monkeypatch):
    routing = _simulate(monkeypatch, SITE_GRAPH, depth=2)["routing_consequence"]
    assert routing["next_hop_withdrawal"]["prefix_count"] == 5
    assert "site_scope" not in routing


def test_sites_affected_names_the_sites_a_denial_reaches_with_no_filter_applied(monkeypatch):
    """`sites_affected` is a rollup with or without a site filter."""
    routing = _simulate(monkeypatch, SITE_GRAPH, depth=2)["routing_consequence"]
    assert routing["sites_affected"] == [
        {"uid": "site:dc1", "name": "Data centre 1"},
        {"uid": "site:hq", "name": "Head office"},
    ]
    assert routing["sites_affected_count"] == 2


def test_a_vrf_with_no_recorded_site_is_counted_not_dropped_from_the_rollup(monkeypatch):
    """The snapshot places `UNSITED_VRF` at no Site."""
    routing = _simulate(monkeypatch, SITE_GRAPH, depth=2)["routing_consequence"]
    assert routing["vrfs_with_no_recorded_site"] == 1
    assert all(site["uid"] != "" for site in routing["sites_affected"])


def test_a_site_filter_stops_the_walk_at_the_boundary_and_counts_what_it_cut(monkeypatch):
    routing = _simulate(monkeypatch, SITE_GRAPH, depth=2, sites=["HQ"])["routing_consequence"]
    assert _withdrawn_prefixes(routing) == ["10.10.10.1/32", "172.16.0.0/16"]

    scope = routing["site_scope"]
    assert scope["sites_requested"] == ["HQ"]
    assert scope["sites_resolved"] == ["site:hq"]
    assert scope["sites_not_found"] == []
    assert scope["vrfs_in_scope"] == 1
    assert scope["vrfs_outside_the_selected_sites"] == 2
    assert scope["vrfs_with_no_recorded_site"] == 1
    assert scope["stopped_the_walk"] is True
    # two in the DC VRF and one in UNSITED_VRF
    assert scope["prefixes_not_followed"] == 3
    assert scope["withdrawn_route_edges_not_followed"] == 3
    assert sorted(scope["vrfs_not_followed"]) == [DC_VRF, UNSITED_VRF]
    assert scope["vrfs_not_followed_count"] == 2
    assert "narrows the question, not the estate" in scope["note"]
    assert "3 prefix(es) in 2 VRF(s) outside the selected sites" in scope["note"]


def test_a_narrow_site_filter_never_reads_as_a_small_blast_radius(monkeypatch):
    whole = _simulate(monkeypatch, SITE_GRAPH, depth=2)["routing_consequence"]
    narrow = _simulate(monkeypatch, SITE_GRAPH, depth=2, sites=["HQ"])["routing_consequence"]

    assert narrow["next_hop_withdrawal"]["prefix_count"] < whole["next_hop_withdrawal"]["prefix_count"]
    assert (
        narrow["next_hop_withdrawal"]["prefix_count"] + narrow["site_scope"]["prefixes_not_followed"]
        == whole["next_hop_withdrawal"]["prefix_count"]
    )
    assert narrow["walk"]["complete"] is False
    assert "site_boundary" in narrow["walk"]["limits"]
    assert narrow["walk"]["prefixes_not_followed_at_the_site_boundary"] == 3
    assert "the site boundary" in narrow["headline"]
    assert "part of the consequence and not all of it" in narrow["headline"]
    assert "smaller than the consequence" in narrow["walk"]["note"]


def test_a_site_the_snapshot_does_not_hold_is_named(monkeypatch):
    routing = _simulate(monkeypatch, SITE_GRAPH, sites=["HQ", "Branch 12"])["routing_consequence"]
    scope = routing["site_scope"]
    assert scope["sites_not_found"] == ["Branch 12"]
    assert scope["sites_resolved"] == ["site:hq"]
    assert "Branch 12 matched no Site in this snapshot" in scope["note"]


def test_a_site_is_named_by_uid_code_or_name(monkeypatch):
    for named in ("site:dc1", "DC1", "dc1", "Data centre 1"):
        routing = _simulate(monkeypatch, SITE_GRAPH, sites=[named])["routing_consequence"]
        assert routing["site_scope"]["sites_resolved"] == ["site:dc1"], named


def test_a_result_a_limit_stopped_is_told_from_a_complete_one_by_a_machine(monkeypatch):
    stopped = _simulate(monkeypatch, DEEP_GRAPH, depth=2)["routing_consequence"]["walk"]
    assert stopped["complete"] is False
    assert stopped["limits"] == ["depth"]
    assert stopped["prefixes_not_followed_at_the_depth_limit"] == 1
    assert stopped["prefixes_not_followed_at_the_site_boundary"] == 0

    whole = _simulate(monkeypatch, DEEP_GRAPH, depth=8)["routing_consequence"]["walk"]
    assert whole["complete"] is True
    assert whole["limits"] == []
    assert whole["prefixes_not_followed_at_the_depth_limit"] == 0

    both = _simulate(monkeypatch, SITE_GRAPH, depth=1, sites=["HQ"])["routing_consequence"]["walk"]
    assert both["complete"] is False
    assert both["limits"] == ["depth", "site_boundary"]


# --- explicit routing intents drive the routing prediction ------------------
#
# The stand-in for `simul_read.read_rib_input` answers a fixed two-peer input.

SHUT = {"kind": "bgp_session.shut", "params": {"session": "bgp:a:1"}}

INTENT_ROWS: dict[str, Any] = {
    **CATALOG_ROWS,
    "(b:BgpSession:Obj {uid: $sess, collection_ts: $snap})": [
        {"context_uid": "vrf:a:default", "device_uids": ["dev:a"]}
    ],
}


def _two_peer_rib_input() -> Any:
    from hst.simul import rib as ribmod
    from hst.simul.propagate import SimulationInput

    def path(session_uid: str, prefix: str, next_hop: str, as_path: str) -> dict[str, Any]:
        return {
            "session_uid": session_uid,
            "direction": "received",
            "prefix": prefix,
            "next_hop": next_hop,
            "next_hop_context_uid": None,
            "as_path": as_path,
            "local_pref": 100,
            "med": None,
            "origin": "igp",
            "communities": None,
            "path_id": None,
        }

    return ribmod.RibInput(
        contexts=[{"uid": "vrf:a:default", "device_uid": "dev:a", "name": "default", "platform": "nxos"}],
        connected=[
            {"context_uid": "vrf:a:default", "prefix": "192.168.2.0/24", "interface": "eth0"},
            {"context_uid": "vrf:a:default", "prefix": "10.7.0.0/24", "interface": "eth1"},
        ],
        bgp=SimulationInput(
            processes=[
                {
                    "uid": "rp:a",
                    "context_uid": "vrf:a:default",
                    "proto": "bgp",
                    "asn": 65001,
                    "router_id": "10.0.0.1",
                    "platform": "nxos",
                }
            ],
            sessions=[
                {
                    "uid": "bgp:a:1",
                    "process_uid": "rp:a",
                    "local_asn": 65001,
                    "peer_asn": 65002,
                    "local_ip": "192.168.2.1",
                    "peer_ip": "192.168.2.35",
                },
                {
                    "uid": "bgp:a:2",
                    "process_uid": "rp:a",
                    "local_asn": 65001,
                    "peer_asn": 65003,
                    "local_ip": "10.7.0.2",
                    "peer_ip": "10.7.0.1",
                },
            ],
        ),
        observed_paths=[
            path("bgp:a:1", "203.0.113.0/24", "192.168.2.35", "65002"),
            path("bgp:a:2", "203.0.113.0/24", "10.7.0.1", "65003 65003"),
            path("bgp:a:2", "10.0.0.0/8", "10.7.0.1", "65003"),
        ],
        direction_status={("bgp:a:1", "received"): "complete", ("bgp:a:2", "received"): "complete"},
    )


def _install_rib_read(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Replace the graph read behind the routing prediction with the two-peer
    input, recording what it was asked for."""
    from hst.simul.errors import ErrorSink

    asked: list[dict[str, Any]] = []

    def read_rib_input(session: Any, **kw: Any) -> simul_read.RibGraphInput:
        asked.append(dict(kw))
        return simul_read.RibGraphInput(_two_peer_rib_input(), list(kw.get("contexts") or []), ErrorSink())

    monkeypatch.setattr(simul_read, "read_rib_input", read_rib_input)
    return asked


def _fake_trace_recording_session_and_rib(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, Any]]:
    """The tracer stand-in, recording the session and the `rib` each trace was
    handed, and drawing a hop on the changed device so the flow is one the
    change bears on."""
    seen: list[tuple[Any, Any]] = []

    def trace(
        session: Any,
        src: str,
        dst: str,
        port: Any = None,
        proto: str = "tcp",
        rib: Any = None,
        gateways: Any = None,
    ) -> dict[str, Any]:
        seen.append((session, rib))
        return {
            "verdict": f"permitted {src}->{dst}",
            "indeterminate": False,
            "warnings": [],
            "legs": [{"blocked": False}],
            "hops": [{"uid": "dev:a", "kind": "Device"}],
        }

    monkeypatch.setattr(pathmod, "trace", trace)
    return seen


def test_an_explicit_session_shutdown_runs_the_routing_calculation_before_and_after(monkeypatch):
    """The prefix stays through the other peer."""
    from hst.simul import rib as ribmod

    _install(monkeypatch, INTENT_ROWS)
    asked = _install_rib_read(monkeypatch)
    seen = _fake_trace_recording_session_and_rib(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[SHUT], flows=[{"src": "10.0.0.5", "dst": "203.0.113.7"}]
    )
    assert asked == [
        {
            "contexts": ["vrf:a:default"],
            "changed": ["vrf:a:default"],
            "ospf_routers": [],
            "rib_source": None,
            "bgp_source": None,
            "ospf_source": None,
        }
    ]

    prediction = body["routing_prediction"]
    assert prediction["evaluation"] == "integrated-routing"
    assert prediction["scopes_predicted"] == ["vrf:a:default"]
    assert prediction["intents"] == [SHUT]
    assert prediction["predicted_withdrawn_count"] == 1
    assert [(r["prefix"], r["next_hop"]) for r in prediction["predicted_prefixes_withdrawn"]] == [
        ("203.0.113.0/24", "192.168.2.35")
    ]
    assert [(r["prefix"], r["next_hop"]) for r in prediction["predicted_prefixes_added"]] == [
        ("203.0.113.0/24", "10.7.0.1")
    ]
    assert prediction["predicted_rows_changed"] == []
    # nothing observed to validate against: every computed row is unverified
    assert prediction["validation_summary"] == {"not-observed": 4}
    assert prediction["rounds_before"] >= 2 and prediction["rounds_after"] >= 2

    # each side reads the calculation's own FIB, before and after the intents,
    # so the comparison is the calculation against itself
    (before_session, before_rib), (after_session, after_rib) = seen
    assert isinstance(before_session, fw_overlay_read.OverlaySession)
    # the FIB for the tables it covers, the side store for the rest
    assert isinstance(before_rib, fw_overlay_read._ScopedRib) and isinstance(before_rib._fib, ribmod.Fib)
    assert isinstance(after_session, fw_overlay_read.OverlaySession)
    # the FIB for the tables it covers, the side store for the rest
    assert isinstance(after_rib, fw_overlay_read._ScopedRib) and isinstance(after_rib._fib, ribmod.Fib)
    assert before_rib is not after_rib
    assert [r["next_hop"] for r in before_rib.lpm("dev:a", "vrf:a:default", "203.0.113.7")] == [
        "192.168.2.35"
    ]
    assert [r["next_hop"] for r in after_rib.lpm("dev:a", "vrf:a:default", "203.0.113.7")] == ["10.7.0.1"]
    assert body["changed_devices"] == ["dev:a"]
    assert body["flows"][0]["crosses_a_changed_device"] is True
    # the change set holds no deny
    assert "routing_consequence" not in body
    assert "routing-consequence-not-evaluated" not in {e["kind"] for e in body["model_errors"]}


def test_the_after_trace_reads_the_calculations_routes_for_a_table_it_covers(monkeypatch):
    """`ChangeSet.route_rows` hands the tracer's route read the after-FIB rows
    of a covered table in the read's own shape, and leaves a table the
    calculation did not cover as collected."""
    graph = _install(monkeypatch, INTENT_ROWS)
    _install_rib_read(monkeypatch)
    captured: dict[str, Any] = {}

    def trace(
        session: Any,
        src: str,
        dst: str,
        port: Any = None,
        proto: str = "tcp",
        rib: Any = None,
        gateways: Any = None,
    ) -> dict:
        if isinstance(session, fw_overlay_read.OverlaySession):
            # the fake `_read` answers the collected rows; the overlay hook
            # `path.session._read` would apply is applied here the same way
            query = "MATCH (v:VrfInstance {uid: $vrf})-[r:STATIC_ROUTE|LEARNED_ROUTE|ORIGINATES]->(p:Prefix)"
            for name, table in (("covered", "vrf:a:default"), ("elsewhere", "vrf:b:default")):
                collected = pathmod._read(session, query, vrf=table)
                captured[name] = session.overlay(query, {"vrf": table}, collected)
        return {"verdict": "permitted", "indeterminate": False, "warnings": [], "legs": [], "hops": []}

    monkeypatch.setattr(pathmod, "trace", trace)
    graph.answers["STATIC_ROUTE|LEARNED_ROUTE|ORIGINATES"] = lambda params: [
        {
            "uid": f"pfx:{params['vrf']}",
            "cidr": "192.168.2.0/24",
            "kind": "ORIGINATES",
            "next_hop": None,
            "ifname": None,
            "egress_uid": "if:eth0",
            "egress_name": "eth0",
        }
    ]
    fw_overlay_read.simulate_change(
        object(), intents=[SHUT], flows=[{"src": "10.0.0.5", "dst": "203.0.113.7"}]
    )

    covered = {(r["cidr"], r["kind"], r["next_hop"], r["uid"]) for r in captured["covered"]}
    assert covered == {
        ("10.7.0.0/24", "ORIGINATES", None, None),
        ("192.168.2.0/24", "ORIGINATES", None, "pfx:vrf:a:default"),
        ("10.0.0.0/8", "LEARNED_ROUTE", "10.7.0.1", None),
        ("203.0.113.0/24", "LEARNED_ROUTE", "10.7.0.1", None),
    }
    assert all(r["rib"] is True for r in captured["covered"])
    assert [r["uid"] for r in captured["elsewhere"]] == ["pfx:vrf:b:default"]


def test_an_ospf_intent_naming_no_router_in_the_snapshot_scopes_nothing_and_says_so(monkeypatch):
    _install(monkeypatch, INTENT_ROWS)
    asked = _install_rib_read(monkeypatch)
    _fake_trace_recording_session_and_rib(monkeypatch)
    intent = {
        "kind": "ospf.interface_cost",
        "params": {"router_id": "10.255.0.9", "address": "10.0.12.1", "cost": 50},
    }
    body = fw_overlay_read.simulate_change(
        object(), intents=[intent], flows=[{"src": "10.0.0.5", "dst": "203.0.113.7"}]
    )
    assert asked == []
    assert body["routing_prediction"]["scopes_predicted"] == []
    assert body["routing_prediction"]["predicted_withdrawn_count"] == 0
    assert "routing-intent-names-no-router" in {e["kind"] for e in body["model_errors"]}


def test_a_routing_intent_missing_its_parameters_is_refused(monkeypatch):
    _install(monkeypatch, INTENT_ROWS)
    with pytest.raises(ProposalError, match="needs a session"):
        fw_overlay_read.simulate_change(
            object(), intents=[{"kind": "bgp_session.shut", "params": {}}], flows=[{"src": "a", "dst": "b"}]
        )
    with pytest.raises(ProposalError, match="needs router_a and router_b"):
        fw_overlay_read.simulate_change(
            object(),
            intents=[{"kind": "ospf.adjacency_down", "params": {"router_a": "10.255.0.1"}}],
            flows=[{"src": "a", "dst": "b"}],
        )


def test_an_address_match_alone_runs_no_routing_calculation(monkeypatch):
    """The calculation runs only for an explicit routing intent."""
    _install(monkeypatch, ROUTE_ROWS)
    asked = _install_rib_read(monkeypatch)
    _fake_trace(monkeypatch)
    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}]
    )
    assert asked == []
    assert "routing_prediction" not in body
    assert body["routing_consequence"]["predicted_prefixes_withdrawn"] == []
