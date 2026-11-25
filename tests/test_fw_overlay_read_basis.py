"""The change simulation's catalog read, FIB egress, derived flows and the basis
of its before/after comparison."""

from typing import Any

import pytest
from tests.support.cputime import cpu_time
from tests.test_fw_overlay_read import (
    CATALOG_ROWS,
    DENY,
    INTENT_ROWS,
    NO_BGP_ROWS,
    SHUT,
    _install,
    _install_rib_read,
)

from hst import path as pathmod
from hst.app import fw_overlay_read
from hst.simul import rib as ribmod
from hst.simul.fw_overlay import DeniedAddresses

# --- the catalog read is bounded by what the intents name ------------------------


def test_the_catalog_queries_carry_no_cross_product_of_the_two_edge_lists():
    for query in (fw_overlay_read._NET_OBJECTS, fw_overlay_read._SVC_OBJECTS):
        assert "OPTIONAL MATCH" not in query
        assert "coalesce(" not in query.split("RETURN")[0]
    assert "[(o)-[rt:RESOLVES_TO]->(t)" in fw_overlay_read._NET_OBJECTS
    assert "[(o)<-[mo:MEMBER_OF]-(m:NetObject)" in fw_overlay_read._NET_OBJECTS


def _group_answers(members: dict[str, list[str]], addrs: dict[str, list[str]]) -> Any:
    def rows(params: dict[str, Any]) -> list[dict[str, Any]]:
        known = set(members) | set(addrs)
        asked = [u for u in params["uids"] if u in known] + [
            u for u in known if u in params.get("names", ()) and u not in params["uids"]
        ]
        return [
            {
                "uid": u,
                "name": u.upper(),
                "ranges": [],
                "addrs": addrs.get(u, []),
                "members": members.get(u, []),
            }
            for u in sorted(set(asked))
        ]

    return rows


def _netobject_calls(graph: Any) -> list[dict[str, Any]]:
    return [p for q, p in graph.calls if "MATCH (o:NetObject:Obj)" in q]


def test_only_the_objects_an_intent_names_are_read_and_group_members_a_round_at_a_time(monkeypatch):
    graph = _install(
        monkeypatch,
        {
            "MATCH (o:NetObject:Obj)": _group_answers(
                {"g": ["m1", "m2"], "m1": ["m3"]}, {"m2": ["10.0.0.2"], "m3": ["10.0.0.3"]}
            )
        },
    )
    intent = {
        "kind": "fw_rule.add",
        "params": {
            "rulebase": "fw:LAN",
            "position": 1,
            "action": "drop",
            "source": "any",
            "destination": "g",
        },
    }

    catalog = fw_overlay_read.read_catalog(object(), [intent])

    calls = _netobject_calls(graph)
    assert len(calls) == 3  # the group, its members, theirs
    assert "g" in calls[0]["names"] and "g" in calls[0]["uids"]
    # the member rounds ask by uid only, over a text with no `name` disjunct
    # (an index seek, not a scan of the label)
    assert calls[1] == {"uids": ["m1", "m2"]}
    assert calls[2] == {"uids": ["m3"]}
    member_queries = [q for q, p in graph.calls if "MATCH (o:NetObject:Obj)" in q][1:]
    assert member_queries and all(q == fw_overlay_read._NET_MEMBERS for q in member_queries)
    assert "o.name IN" not in fw_overlay_read._NET_MEMBERS
    assert "s.name IN" not in fw_overlay_read._SVC_MEMBERS
    assert sorted(catalog.net_addresses("g")) == ["10.0.0.2", "10.0.0.3"]


def test_a_literal_address_is_not_looked_up_as_an_object(monkeypatch):
    graph = _install(monkeypatch, {})
    fw_overlay_read.read_catalog(object(), [DENY])
    (call,) = _netobject_calls(graph)
    assert "192.168.2.35" not in call["names"] and "192.168.2.35" not in call["uids"]
    assert "any" not in call["names"]


def test_a_membership_cycle_ends_the_rounds(monkeypatch):
    graph = _install(
        monkeypatch,
        {"MATCH (o:NetObject:Obj)": _group_answers({"a": ["b"], "b": ["a"]}, {"a": ["10.0.0.1"]})},
    )
    intent = {"kind": "fw_rule.add", "params": {**DENY["params"], "destination": "a"}}

    catalog = fw_overlay_read.read_catalog(object(), [intent])

    assert len(_netobject_calls(graph)) == 2
    assert catalog.net_addresses("a") == ["10.0.0.1"]


def test_the_service_and_zone_reads_are_bounded_the_same_way(monkeypatch):
    graph = _install(monkeypatch, {})
    intent = {
        "kind": "fw_rule.add",
        "params": {**DENY["params"], "services": "WEB", "from_zone": "LAN"},
    }
    fw_overlay_read.read_catalog(object(), [intent])
    for fragment in ("MATCH (s:SvcObject:Obj)", "MATCH (z:Zone:Obj)"):
        (call,) = [p for q, p in graph.calls if fragment in q]
        assert {"WEB", "LAN"} <= set(call["names"])
        assert "ORDER BY" not in next(q for q, _p in graph.calls if fragment in q)


# --- a FIB row keeps the egress of its own next hop ------------------------------


class _Fib:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def table(self, uid: str) -> list[dict[str, Any]]:
        return self._rows


def _learned(next_hop: str, ifname: str) -> dict[str, Any]:
    return {
        "uid": "pfx:198.51.100.0/24",
        "cidr": "198.51.100.0/24",
        "kind": "LEARNED_ROUTE",
        "next_hop": next_hop,
        "ifname": ifname,
        "egress_uid": f"if:r1:{ifname}",
        "egress_name": ifname,
    }


def _fib(rows: list[dict[str, Any]], collected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return fw_overlay_read._fib_route_rows(_Fib(rows))("vrf:r1", collected)


CONNECTED = [
    {"prefix": "192.0.2.0/30", "protocol": "connected", "interface": "eth0"},
    {"prefix": "192.0.2.4/30", "protocol": "connected", "interface": "eth1"},
]


def test_a_route_moved_to_another_next_hop_takes_the_egress_collected_for_that_next_hop():
    collected = [_learned("192.0.2.1", "eth0"), _learned("192.0.2.6", "eth1")]
    fib = [*CONNECTED, {"prefix": "198.51.100.0/24", "protocol": "bgp", "next_hop": "192.0.2.6"}]

    (row,) = [r for r in _fib(fib, collected) if r["cidr"] == "198.51.100.0/24"]

    assert (row["next_hop"], row["ifname"], row["egress_uid"]) == ("192.0.2.6", "eth1", "if:r1:eth1")
    assert row["uid"] == "pfx:198.51.100.0/24"


def test_a_route_moved_to_a_next_hop_nothing_was_collected_for_leaves_by_the_interface_it_resolves_through():
    collected = [_learned("192.0.2.1", "eth0"), {**_learned("192.0.2.9", "eth9"), "egress_uid": None}]
    collected[0]["egress_uid"] = "if:r1:eth0"
    fib = [*CONNECTED, {"prefix": "198.51.100.0/24", "protocol": "bgp", "next_hop": "192.0.2.6"}]

    (row,) = [r for r in _fib(fib, collected) if r["cidr"] == "198.51.100.0/24"]

    # not eth0, the interface towards the old next hop: the table puts .6 on eth1
    assert (row["ifname"], row["egress_name"]) == ("eth1", "eth1")
    assert row["egress_uid"] is None  # the tracer resolves it from the name on the device
    assert row["uid"] == "pfx:198.51.100.0/24"


def test_a_next_hop_the_table_resolves_through_two_interfaces_names_none():
    fib = [
        *CONNECTED,
        {"prefix": "192.0.2.0/24", "protocol": "ospf", "next_hop": "192.0.2.2", "interface": "eth7"},
        {"prefix": "192.0.2.0/24", "protocol": "ospf", "next_hop": "192.0.2.2", "interface": "eth8"},
        {"prefix": "198.51.100.0/24", "protocol": "bgp", "next_hop": "192.0.2.77"},
    ]
    (row,) = [r for r in _fib(fib, [_learned("192.0.2.1", "eth0")]) if r["cidr"] == "198.51.100.0/24"]
    assert row["ifname"] is None and row["egress_uid"] is None


def test_a_next_hop_is_followed_through_the_route_that_resolves_it():
    fib = [
        *CONNECTED,
        {"prefix": "10.255.0.3/32", "protocol": "ospf", "next_hop": "192.0.2.6", "interface": "eth1"},
        {"prefix": "172.16.0.0/16", "protocol": "bgp", "next_hop": "10.255.0.3"},
    ]
    (row,) = [r for r in _fib(fib, []) if r["cidr"] == "172.16.0.0/16"]
    assert row["ifname"] == "eth1"


class _Tables:
    def __init__(self, tables: dict[str, list[dict[str, Any]]]) -> None:
        self._tables = tables

    def table(self, uid: str) -> list[dict[str, Any]] | None:
        return self._tables.get(uid)


LEAKED = {
    "prefix": "198.51.100.0/24",
    "protocol": "bgp",
    "next_hop": "10.255.0.2",
    "next_hop_context_uid": "vrf:B",
}
IMPORTING = [
    {"prefix": "0.0.0.0/0", "protocol": "static", "next_hop": "192.0.2.9", "interface": "eth9"},
    LEAKED,
]


def test_a_leaked_route_resolves_its_next_hop_in_the_exporting_table():
    """Not through the importing table's default route out of eth9."""
    exporting = [{"prefix": "10.255.0.0/24", "protocol": "connected", "interface": "eth3"}]
    fib = _Tables({"vrf:r1": IMPORTING, "vrf:B": exporting})
    collected = [{**_learned("192.0.2.9", "eth9"), "cidr": "0.0.0.0/0"}]
    (row,) = [r for r in fib_rows(fib, collected) if r["cidr"] == "198.51.100.0/24"]
    assert (row["ifname"], row["egress_uid"], row["next_hop_vrf"]) == ("eth3", None, "vrf:B")


def test_a_leaked_route_whose_exporting_table_is_not_calculated_names_no_interface():
    collected = [{**_learned("192.0.2.9", "eth9"), "cidr": "0.0.0.0/0"}]
    (row,) = [
        r for r in fib_rows(_Tables({"vrf:r1": IMPORTING}), collected) if r["cidr"] == "198.51.100.0/24"
    ]
    assert row["ifname"] is None and row["egress_uid"] is None


def fib_rows(fib: Any, collected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return fw_overlay_read._fib_route_rows(fib)("vrf:r1", collected)


def test_a_large_table_of_routes_without_an_interface_is_rewritten_in_linear_time():
    """One longest-prefix index per read, not a scan of the table per row."""
    n = 4000
    fib = [
        {"prefix": "10.0.0.0/30", "protocol": "connected", "interface": "eth0"},
        *(
            {"prefix": f"172.{16 + i // 256}.{i % 256}.0/24", "protocol": "bgp", "next_hop": "10.0.0.2"}
            for i in range(n)
        ),
    ]
    with cpu_time() as spent:
        rows = _fib(fib, [])
    assert all(r["ifname"] == "eth0" for r in rows)
    assert spent.seconds < 3.0, f"rewrite of {n} routes took {spent.seconds:.1f} s of CPU time"


def test_a_connected_prefix_keeps_its_prefix_uid_and_egress():
    collected = [
        {
            "uid": "pfx:192.0.2.0/30",
            "cidr": "192.0.2.0/30",
            "kind": "ORIGINATES",
            "next_hop": None,
            "ifname": "eth0",
            "egress_uid": "if:r1:eth0",
            "egress_name": "eth0",
        }
    ]
    (row,) = [r for r in _fib(CONNECTED, collected) if r["cidr"] == "192.0.2.0/30"]
    assert (row["uid"], row["egress_uid"]) == ("pfx:192.0.2.0/30", "if:r1:eth0")


# --- derived flows cross the changed device --------------------------------------


def test_a_destination_deny_is_traced_from_the_outside_and_from_behind_the_other_interfaces():
    denied = DeniedAddresses(to_specs=["10.1.1.5"], from_specs=[])
    flows, untraced = fw_overlay_read._derived_flows(
        denied, (), ["10.2.0.0/24", "10.1.1.0/24", "2001:db8::/64"]
    )
    assert flows == [{"src": "0.0.0.0/0", "dst": "10.1.1.5"}, {"src": "10.2.0.0/24", "dst": "10.1.1.5"}]
    assert untraced == 0


def test_the_default_route_is_of_the_family_of_the_denied_address():
    denied = DeniedAddresses(to_specs=["2001:db8::35"], from_specs=["2001:db8:1::5"])
    flows, _ = fw_overlay_read._derived_flows(denied, (), ["10.2.0.0/24", "2001:db8:2::/64"])
    assert {"src": "::/0", "dst": "2001:db8::35"} in flows
    assert {"src": "2001:db8:2::/64", "dst": "2001:db8::35"} in flows
    assert {"src": "2001:db8:1::5", "dst": "::/0"} in flows
    assert not any(f["dst"] == "0.0.0.0/0" or f["src"] == "0.0.0.0/0" for f in flows)


def test_a_source_deny_is_traced_towards_the_default_route_and_the_denied_destinations():
    denied = DeniedAddresses(to_specs=["192.168.2.40"], from_specs=["192.168.2.35"])
    flows, _ = fw_overlay_read._derived_flows(denied, (), ())
    assert {"src": "192.168.2.35", "dst": "0.0.0.0/0"} in flows
    assert {"src": "192.168.2.35", "dst": "192.168.2.40"} in flows
    assert {"src": "0.0.0.0/0", "dst": "192.168.2.40"} in flows


def _trace_with_rulebase(decided: bool, traced: list[tuple[str, str]]) -> Any:
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
        traced.append((src, dst))
        leg: dict[str, Any] = (
            {"blocked": overlaid, "firewall": "LAN drop"} if overlaid else {"blocked": False}
        )
        if decided and overlaid:
            leg["fw_uid"] = "fw:LAN"
        return {
            "verdict": "blocked" if overlaid else "permitted",
            "indeterminate": False,
            "warnings": [],
            "legs": [leg],
            "hops": [{"kind": "Device", "uid": "dev:core1"}],
        }

    return trace


DEVICE_ROWS: dict[str, Any] = {
    **NO_BGP_ROWS,
    "MATCH (d:Device)-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})": [
        {"uid": "dev:core1"}
    ],
    "MATCH (i:Interface)-[o:ON]->(d:Device:Obj {uid: $dev, collection_ts: $snap})": [
        {
            "uid": "if:eth0",
            "name": "eth0",
            "prefixes": ["192.168.2.0/24"],
            "bridge_domain_ips": [],
            "attached_ips": [],
        },
        {
            "uid": "if:eth1",
            "name": "eth1",
            "prefixes": ["10.2.0.0/24"],
            "bridge_domain_ips": [],
            "attached_ips": [],
        },
    ],
}


def test_the_derived_flows_of_a_destination_deny_start_behind_the_changed_device(monkeypatch):
    _install(monkeypatch, DEVICE_ROWS)
    traced: list[tuple[str, str]] = []
    monkeypatch.setattr(pathmod, "trace", _trace_with_rulebase(True, traced))

    body = fw_overlay_read.simulate_change(object(), intents=[DENY], flows=[])

    pairs = set(traced)
    assert ("10.2.0.0/24", "192.168.2.35") in pairs
    assert ("0.0.0.0/0", "192.168.2.35") in pairs
    # the prefix that holds the denied address is not a source that crosses the router
    assert not any(src == "192.168.2.0/24" for src, _dst in pairs)
    assert all(not f["basis_uncertain"] for f in body["flows"])
    assert body["results_changed"] == body["flow_count"] > 0


def test_a_derived_flow_no_changed_rulebase_decides_is_not_counted_and_the_answer_says_so(monkeypatch):
    _install(monkeypatch, DEVICE_ROWS)
    traced: list[tuple[str, str]] = []
    monkeypatch.setattr(pathmod, "trace", _trace_with_rulebase(False, traced))

    body = fw_overlay_read.simulate_change(object(), intents=[DENY], flows=[])

    assert body["flow_count"] > 0
    assert all(f["basis_uncertain"] for f in body["flows"])
    assert all(f["result_changed"] for f in body["flows"])
    assert body["results_changed"] == 0
    assert body["results_not_established"] == body["flow_count"]
    assert body["flows"][0]["model_error"]["kind"] == "flow-result-not-established"
    assert "derived-flows-not-decided-by-the-change" in {e["kind"] for e in body["model_errors"]}


def test_a_supplied_flow_is_not_marked_for_the_rulebase_that_decided_it(monkeypatch):
    _install(monkeypatch, DEVICE_ROWS)
    monkeypatch.setattr(pathmod, "trace", _trace_with_rulebase(False, []))

    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}]
    )

    assert body["flows"][0]["basis_uncertain"] is False
    assert body["results_changed"] == 1


# --- both sides over the calculation, and an unsettled one is no answer ---------


def _trace_by_next_hop(seen: list[tuple[Any, Any]]) -> Any:
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
        # the calculation's FIB reaches the tracer through `_ScopedRib`
        rows = rib.lpm("dev:a", "vrf:a:default", dst) if rib is not None else []
        via = rows[0]["next_hop"] if rows else "collected"
        return {
            "verdict": f"permitted via {via}",
            "indeterminate": False,
            "warnings": [],
            "legs": [{"blocked": False}],
            "hops": [{"uid": "dev:a", "kind": "Device"}],
        }

    return trace


def _verified(monkeypatch: pytest.MonkeyPatch) -> None:
    """The calculation's before state agrees with the observed RIB for every
    route, and its after state carries no gap."""
    real = ribmod.compute

    def compute(inp: Any, errors: Any = None, **kw: Any) -> Any:
        result = real(inp, errors, **kw)
        result.validation = [{**row, "status": "match"} for row in result.validation]
        result.gaps = []
        return result

    monkeypatch.setattr(ribmod, "compute", compute)


def test_a_flow_the_calculation_moves_is_counted_when_its_basis_is_validated(monkeypatch):
    _install(monkeypatch, INTENT_ROWS)
    _install_rib_read(monkeypatch)
    _verified(monkeypatch)
    seen: list[tuple[Any, Any]] = []
    monkeypatch.setattr(pathmod, "trace", _trace_by_next_hop(seen))

    body = fw_overlay_read.simulate_change(
        object(), intents=[SHUT], flows=[{"src": "10.0.0.5", "dst": "203.0.113.7"}]
    )

    (flow,) = body["flows"]
    assert flow["before"]["detail"] == "permitted via 192.168.2.35"
    assert flow["after"]["detail"] == "permitted via 10.7.0.1"
    assert flow["basis_uncertain"] is False
    assert (body["results_changed"], body["results_not_established"]) == (1, 0)


def test_a_flow_whose_route_the_observed_rib_does_not_confirm_is_not_established(monkeypatch):
    _install(monkeypatch, INTENT_ROWS)
    _install_rib_read(monkeypatch)
    monkeypatch.setattr(pathmod, "trace", _trace_by_next_hop([]))

    body = fw_overlay_read.simulate_change(
        object(), intents=[SHUT], flows=[{"src": "10.0.0.5", "dst": "203.0.113.7"}]
    )

    (flow,) = body["flows"]
    assert flow["result_changed"] is True  # the boolean stays what the two traces show
    assert flow["basis_uncertain"] is True
    assert "route 203.0.113.0/24 in vrf:a:default is not-observed" in flow["basis_uncertain_reasons"]
    assert flow["model_error"]["kind"] == "flow-result-not-established"
    assert (body["results_changed"], body["results_not_established"]) == (0, 1)
    assert body["paths_changed"] == 0
    assert "flow-result-not-established" in {e["kind"] for e in body["model_errors"]}


def test_a_flow_that_crosses_none_of_the_contexts_with_an_unconfirmed_route_is_not_held_back(monkeypatch):
    _install(monkeypatch, INTENT_ROWS)
    _install_rib_read(monkeypatch)
    seen: list[tuple[Any, Any]] = []
    trace = _trace_by_next_hop(seen)

    def elsewhere(*args: Any, **kwargs: Any) -> dict[str, Any]:
        result = trace(*args, **kwargs)
        result["hops"] = [{"uid": "dev:other", "kind": "Device"}]
        return result

    monkeypatch.setattr(pathmod, "trace", elsewhere)

    body = fw_overlay_read.simulate_change(
        object(), intents=[SHUT], flows=[{"src": "10.0.0.5", "dst": "203.0.113.7"}]
    )

    assert body["flows"][0]["basis_uncertain"] is False


def test_an_unsettled_calculation_is_not_traced_over_and_no_flow_is_counted(monkeypatch):
    _install(monkeypatch, INTENT_ROWS)
    _install_rib_read(monkeypatch)
    real = ribmod.compute
    calls: list[int] = []

    def compute(inp: Any, errors: Any = None, **kw: Any) -> Any:
        result = real(inp, errors, **kw)
        calls.append(1)
        if len(calls) == 2:  # the after state
            result.convergence = {"status": "cycle", "rounds": 5}
            result.model_errors = [
                *result.model_errors,
                {"kind": "no-routing-fixed-point", "detail": "the state repeated", "subject": None},
            ]
        return result

    monkeypatch.setattr(ribmod, "compute", compute)
    seen: list[tuple[Any, Any]] = []
    monkeypatch.setattr(pathmod, "trace", _trace_by_next_hop(seen))

    body = fw_overlay_read.simulate_change(
        object(), intents=[SHUT], flows=[{"src": "10.0.0.5", "dst": "203.0.113.7"}]
    )

    # neither side reads a FIB the calculation did not settle on
    assert [type(rib) for _s, rib in seen] == [type(None), type(None)]
    kinds = {e["kind"] for e in body["model_errors"]}
    assert "routing-after-state-unsettled" in kinds
    (flow,) = body["flows"]
    assert flow["basis_uncertain"] is True
    assert "did not settle" in flow["basis_uncertain_reasons"][0]
    assert (body["results_changed"], body["results_not_established"]) == (0, 1)
    assert body["routing_prediction"]["convergence_after"]["status"] == "cycle"


def test_a_change_set_with_no_routing_intent_traces_the_collected_routes_on_both_sides(monkeypatch):
    _install(monkeypatch, CATALOG_ROWS)
    seen: list[tuple[Any, Any]] = []
    monkeypatch.setattr(pathmod, "trace", _trace_by_next_hop(seen))

    body = fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "10.0.0.5", "dst": "192.168.2.35"}]
    )

    (before_session, before_rib), _after = seen
    assert not isinstance(before_session, fw_overlay_read.OverlaySession)
    assert before_rib is None
    assert body["flows"][0]["basis_uncertain"] is False


# --- under a routing intent, a table outside the calculation reads the side store


class _Store:
    approximate = False

    def __init__(self, rows: dict[str, list[dict[str, Any]]]) -> None:
        self._rows = rows

    def has_rows(self, device_uid: str) -> bool:
        return device_uid == "dev:r1"

    def coverage(self, device_uid: str) -> str | None:
        return "complete" if device_uid == "dev:r1" else None

    def lpm(self, device_uid: str, context_uid: Any, probe_ip: str, *, legacy_vrf: Any = None) -> list:
        return [dict(r) for r in self._rows.get(str(context_uid), [])]

    def overlapping(self, device_uid, context_uid, lo, hi, minlen, af, *, legacy_vrf=None) -> list:
        return [dict(r) for r in self._rows.get(str(context_uid), [])]


class _CalcFib:
    def has_rows(self, device_uid: str) -> bool:
        return device_uid == "dev:a"

    def covers(self, context_uid: str) -> bool:
        return context_uid == "vrf:a:default"

    def lpm(self, device_uid: str, context_uid: Any, probe_ip: str, *, legacy_vrf: Any = None) -> list:
        return [{"prefix": "10.1.0.0/16", "next_hop": "10.9.9.9", "fib": True}]

    def overlapping(self, device_uid, context_uid, lo, hi, minlen, af, *, legacy_vrf=None) -> list:
        return []


def test_a_table_outside_the_calculation_reads_the_side_store_and_a_covered_one_the_fib():
    store = _Store({"vrf:main": [{"prefix": "10.1.2.0/24", "next_hop": "10.0.0.7"}]})
    rib = fw_overlay_read._ScopedRib(_CalcFib(), store)

    assert rib.lpm("dev:r1", "vrf:main", "10.1.2.3") == [{"prefix": "10.1.2.0/24", "next_hop": "10.0.0.7"}]
    assert rib.has_rows("dev:r1") and rib.coverage("dev:r1") == "complete"
    assert rib.lpm("dev:a", "vrf:a:default", "10.1.2.3")[0]["fib"] is True
    assert rib.coverage("dev:a") == "computed"
    assert rib.covering_lengths(
        [("dev:r1", "vrf:main", "main"), ("dev:a", "vrf:a:default", None)], "10.1.2.3"
    ) == {
        "vrf:main": 24,
        "vrf:a:default": 16,
    }


def test_without_a_side_store_a_table_outside_the_calculation_has_no_rib_rows():
    rib = fw_overlay_read._ScopedRib(_CalcFib(), None)
    assert rib.lpm("dev:r1", "vrf:main", "10.1.2.3") == []
    assert not rib.has_rows("dev:r1") and rib.coverage("dev:r1") is None
