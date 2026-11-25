"""Failures re-run real routing and whole service semantics, without editing observations."""

import pytest
from tests.test_impact_evaluate import (
    CLIENTS,
    R1,
    SESSION_A,
    VRF_R1,
    A,
    B,
    _deny,
    _firewall,
    _network,
    _request,
    ev,
)
from tests.test_impact_evaluate import graph as graph
from tests.test_impact_sessions import network as session_network
from tests.test_impact_sessions import request as session_request
from tests.test_simul_rib import DEV, MAIN, T100, _fib_input, _lsdb, _ospf_entry
from tests.test_simul_rib import R1 as O1
from tests.test_simul_rib import R2 as O2

from hst.assessment.failure_routing import failed_lsdb, transform_routing
from hst.assessment.resilience import apply_failures, search_resilience
from hst.assessment.search import FAILS, HOLDS, UNKNOWN, SearchLimits
from hst.simul import ospf, rib


def test_failed_broker_connector_removed_before_healthy_choice(graph):
    from tests.test_strict_symbolic_gates import _prepare_zpa, _region

    from hst.assessment.resilience import _FailureGates

    segment, identity = _prepare_zpa(graph)
    graph.zpa_connectors[segment] = [{"uid": "conn:a", "health": "up"}, {"uid": "conn:b", "health": "up"}]
    graph.connector_address["conn:a"] = [{"host_uid": A, "ip": "10.0.1.2"}]
    graph.connector_address["conn:b"] = [{"host_uid": B, "ip": "10.0.2.2"}]
    gates = _FailureGates(ev.GraphGates(None), {A}, set(), set())
    effects = [effect for _, effect in gates.broker(identity, segment).apply(_region())]
    assert effects and all(effect.kind == "broker" for effect in effects)
    assert {effect.data["connector"]["uid"] for effect in effects} == {"conn:b"}
    both = _FailureGates(ev.GraphGates(None), {A, B}, set(), set())
    assert [effect.kind for _, effect in both.broker(identity, segment).apply(_region())] == ["deny"]


def test_graph_confirmed_connector_target_does_not_need_a_routing_context(graph, monkeypatch):
    from dataclasses import replace
    from types import SimpleNamespace

    from tests.test_strict_symbolic_gates import _prepare_zpa, _region

    from hst import path
    from hst.assessment.resilience import _BROKER_FAILURE_TARGET

    segment, identity = _prepare_zpa(graph)
    graph.zpa_connectors[segment] = [{"uid": "connector:only", "health": "up"}]
    graph.connector_address["connector:only"] = [{"host_uid": "vm:connector", "ip": "192.0.2.10"}]
    read = path._read
    monkeypatch.setattr(
        path,
        "_read",
        lambda session, query, **params: (
            [{"uid": params["uid"]}] if query == _BROKER_FAILURE_TARGET else read(session, query, **params)
        ),
    )
    net = replace(_network(), gates=ev.GraphGates(SimpleNamespace(cts=1000)))
    failed = apply_failures(net, [{"kind": "device", "uid": "connector:only"}])
    assert [effect.kind for _, effect in failed.gates.broker(identity, segment).apply(_region())] == ["deny"]


@pytest.mark.parametrize(
    ("condition", "survives"),
    [
        (ev.every(ev.member("a"), ev.member("b")), False),
        (ev.any_one(ev.member("a"), ev.member("b")), True),
        (ev.n_of_m(1, ev.member("a"), ev.member("b")), True),
        (ev.n_of_m(2, ev.member("a"), ev.member("b")), False),
    ],
)
def test_service_condition_is_evaluated_after_member_attachment_failure(graph, condition, survives):
    from tests.test_impact_evaluate import _ivals

    request = _request(
        members=(ev.Member("a", _ivals("10.0.1.2")), ev.Member("b", _ivals("10.0.2.2"))), condition=condition
    )
    net = _network()
    assert ev.answer(net, request).lower
    after = ev.answer(apply_failures(net, [{"kind": "device", "uid": A}]), request)
    assert bool(after.lower) is survives
    assert bool(after.upper) is survives


def test_tunnel_failure_disables_the_overlay_and_its_carrier_composition():
    net = session_network(tunnel=True)
    request = session_request("forward")
    assert ev.answer(net, request).lower
    failed = apply_failures(net, [{"kind": "tunnel", "uid": "t1", "interfaces": ["wg1", "wg2"]}])
    assert not ev.answer(failed, request).upper


def test_bgp_device_failure_recomputes_backup_and_removes_failed_advertisements(graph):
    before = _network()
    after = apply_failures(before, [{"kind": "device", "uid": A}])
    result = ev.answer(after, _request())
    assert result.lower == CLIENTS
    assert all(row["session_uid"] != SESSION_A for row in after.routing.observed_paths)
    assert after.routes.fib.lpm(R1, VRF_R1, "203.0.113.10")[0]["next_hop"] == "10.0.2.2"
    assert before.routes.fib.lpm(R1, VRF_R1, "203.0.113.10")[0]["next_hop"] == "10.0.1.2"


def test_nonmonotone_failure_reveals_permitted_backup(graph):
    _firewall(graph, A, "rb:a", [_deny("203.0.113.10")])
    before = _network()
    assert not ev.answer(before, _request()).upper
    assert ev.answer(apply_failures(before, [{"kind": "device", "uid": A}]), _request()).lower == CLIENTS


@pytest.mark.parametrize("success", ["forward", "round-trip", "session"])
def test_shared_firewall_nat_failure_denies_all_success_conditions(success):
    before = session_network(stateful=True, snat=True)
    request = session_request(success)
    assert ev.answer(before, request).lower
    after = apply_failures(before, [{"kind": "device", "uid": "r1"}])
    assert not ev.answer(after, request).upper


def test_conduit_failure_expands_overlapping_nested_domains_and_proves_minimum(graph):
    net = _network()
    targets = [{"id": "a", "kind": "device", "uid": A}, {"id": "b", "kind": "device", "uid": B}]
    domains = [
        {"id": "conduit", "members": ["a", "b"]},
        {"id": "power", "members": ["a"]},
        {"id": "site", "members": ["conduit", "power"]},
    ]

    def oracle(effects):
        return HOLDS if ev.answer(apply_failures(net, effects), _request()).lower else FAILS

    result = search_resilience(targets, domains, oracle, SearchLimits(max_combination_size=5))
    assert result["search_complete"]
    cut = next(f for f in result["findings"] if f["candidates"] == ["conduit"])
    assert cut["minimality"]["minimum_cardinality"]
    assert not result["domain_coverage_established"]
    assert result["unique_physical_scenarios"] == 4


def test_ospf_interface_failure_withdraws_reciprocal_adjacency_and_recomputes_spf():
    model = ospf.LsdbModel.from_rows(_lsdb())
    interface = ev.Interface("r1", "if12", "eth12", "c1", ("10.0.12.0/30",), ("10.0.12.1",))
    assert "192.168.2.0/24" in {r.prefix for r in ospf.calculate(model, O1).routes}
    changed = failed_lsdb(model, set(), {O1: [interface]})
    assert "192.168.2.0/24" not in {r.prefix for r in ospf.calculate(changed, O1).routes}
    assert not any(link.link_id == O1 for link in changed.router_lsa(ospf.BACKBONE, O2).links)
    assert any(link.link_id == O1 for link in model.router_lsa(ospf.BACKBONE, O2).links)


def test_routing_adapter_recomputes_ospf_after_an_interface_failure():
    interfaces = [
        ev.Interface("r1", "if12", "eth12", "c1", ("10.0.12.0/30",), ("10.0.12.1",)),
        ev.Interface("r1", "if13", "eth13", "c1", ("10.0.13.0/30",), ("10.0.13.1",)),
    ]
    original = rib.RibInput(
        contexts=[{"uid": "c1", "device_uid": "r1", "platform": "nxos"}],
        connected=[
            {"context_uid": i.context_uid, "prefix": i.prefixes[0], "interface": i.name} for i in interfaces
        ],
        ospf=[_ospf_entry(context_uid="c1")],
    )
    changed = transform_routing(original, interfaces, set(), {"if12"})
    assert rib.compute(original).fib.lpm("r1", "c1", "192.168.2.1")
    assert not rib.compute(changed).fib.lpm("r1", "c1", "192.168.2.1")


def test_surviving_abr_withdraws_summary_after_remote_area_interface_failure():
    from tests.test_simul_rib import _link, _lsa

    rows = [
        *_lsdb(),
        _lsa("router", O2, O2, area="0.0.0.1", links=[_link("stub", "198.51.100.0", "255.255.255.0", 5)]),
        _lsa("summary", "198.51.100.0", O2, mask="255.255.255.0", metric=5),
    ]
    interfaces = [
        ev.Interface("r1", "if12", "eth12", "c1", ("10.0.12.0/30",), ("10.0.12.1",)),
        ev.Interface("r2", "edge", "edge", "c2", ("198.51.100.0/24",), ("198.51.100.1",)),
    ]
    original = rib.RibInput(
        contexts=[
            {"uid": "c1", "device_uid": "r1", "platform": "nxos"},
            {"uid": "c2", "device_uid": "r2", "platform": "nxos"},
        ],
        ospf=[
            _ospf_entry(context_uid="c1", rows=rows),
            _ospf_entry(context_uid="c2", uid="rp:r2", router_id=O2, rows=rows),
        ],
    )
    before = ospf.calculate(ospf.LsdbModel.from_rows(rows), O1)
    assert "198.51.100.0/24" in {route.prefix for route in before.routes}
    changed = transform_routing(original, interfaces, set(), {"edge"})
    assert not changed.observation_gaps
    assert "198.51.100.0/24" not in {
        route.prefix for route in ospf.calculate(changed.ospf[0]["model"], O1).routes
    }


def test_pbr_target_fib_recomputed_and_binding_retained_until_ingress_fails():
    original = _fib_input()
    interface = ev.Interface(DEV, "wg", "wg0", T100, ("172.16.1.0/30",), ("172.16.1.1",))
    changed = transform_routing(original, [interface], set(), {"wg"})
    assert changed.pbr == original.pbr
    assert rib.compute(original).fib.lpm(DEV, T100, "203.0.113.1")
    assert not rib.compute(changed).fib.lpm(DEV, T100, "203.0.113.1")
    assert rib.compute(changed).fib.lpm(DEV, MAIN, "203.0.113.1")


def test_unrelated_reused_ip_does_not_withdraw_other_vrf_static_route():
    original = rib.RibInput(
        contexts=[{"uid": "a", "device_uid": "a"}, {"uid": "b", "device_uid": "b"}],
        static=[{"context_uid": "b", "prefix": "0.0.0.0/0", "next_hop": "10.0.0.1"}],
    )
    interface = ev.Interface("a", "a", "eth0", "a", ("10.0.0.0/24",), ("10.0.0.1",))
    assert transform_routing(original, [interface], {"a"}, set()).static == original.static


def test_route_leak_withdraws_network_origin_when_its_connected_interface_fails():
    from hst.simul.propagate import SimulationInput

    interface = ev.Interface("r", "if:a", "eth0", "a", ("192.168.10.0/24",), ("192.168.10.1",))
    original = rib.RibInput(
        contexts=[{"uid": c, "device_uid": "r", "platform": "nxos"} for c in ("a", "b")],
        connected=[{"context_uid": "a", "prefix": "192.168.10.0/24", "interface": "eth0"}],
        bgp=SimulationInput(
            processes=[
                {
                    "uid": "rp:a",
                    "proto": "bgp",
                    "context_uid": "a",
                    "asn": 65001,
                    "router_id": "10.255.0.1",
                    "platform": "nxos",
                }
            ],
            local_routes=[
                {
                    "process_uid": "rp:a",
                    "prefix": "192.168.10.0/24",
                    "intent": True,
                    "origin_mechanism": "network",
                }
            ],
        ),
        rt_pairs=[{"importer": "b", "exporter": "a", "via_rt": ["65001:1"]}],
    )
    assert rib.compute(original).fib.lpm("r", "b", "192.168.10.10")
    changed = transform_routing(original, [interface], set(), {"if:a"})
    assert not rib.compute(changed).fib.lpm("r", "b", "192.168.10.10")


def test_cancellation_does_not_report_a_partial_search_as_exhaustive(graph):
    count = 0

    def oracle(effects):
        nonlocal count
        count += 1
        return HOLDS if ev.answer(apply_failures(_network(), effects), _request()).lower else FAILS

    result = search_resilience(
        [{"id": "a", "kind": "device", "uid": A}, {"id": "b", "kind": "device", "uid": B}],
        [],
        oracle,
        cancelled=lambda: count == 2,
    )
    assert result["stop_reason"] == "cancelled" and not result["search_complete"]


def test_inconsistent_aliases_cannot_hide_distinct_endpoint_failures():
    with pytest.raises(ValueError, match="identical endpoint"):
        search_resilience(
            [
                {"id": "one", "kind": "link", "uid": "link", "interfaces": ["if:a"]},
                {"id": "two", "kind": "link", "uid": "link", "interfaces": ["if:b"]},
            ],
            [],
            lambda _: HOLDS,
        )


def _with_l2_switch():
    """The test network plus an L2 switch: two switchports bound to a segment,
    no address, no prefix, no routing context (NX-OS/IOS-XE access switch)."""
    from tests.test_impact_evaluate import _interfaces

    ports = tuple(
        ev.Interface(
            device_uid="sw1",
            uid=f"sw1:p{n}",
            name=f"p{n}",
            context_uid=None,
            prefixes=(),
            addresses=(),
            segments=("seg:transit",),
        )
        for n in (1, 2)
    )
    return _network(interfaces=(*_interfaces(), *ports))


@pytest.mark.parametrize(
    "effect",
    [
        {"kind": "device", "uid": "sw1"},
        {"kind": "interface", "uid": "sw1:p1"},
        {"kind": "link", "uid": "sw-link", "interfaces": ["sw1:p1", "sw1:p2"]},
    ],
)
def test_l2_only_failure_is_not_modeled(graph, effect):
    with pytest.raises(ValueError, match=r"sw1.*L2 forwarding.*not modeled"):
        apply_failures(_with_l2_switch(), [effect])


def test_l2_only_failure_trial_is_unknown_and_no_single_failure_survival_claim(graph):
    net, request = _with_l2_switch(), _request()

    def oracle(effects):
        # the except clause of the resilience oracle in assessment/service.py
        try:
            failed = apply_failures(net, effects)
        except ValueError as exc:
            return {"verdict": UNKNOWN, "reason": str(exc)}
        return HOLDS if ev.answer(failed, request).lower == CLIENTS else FAILS

    result = search_resilience(
        [
            {"id": "switch", "kind": "device", "uid": "sw1"},
            {"id": "port", "kind": "interface", "uid": "sw1:p1"},
        ],
        [],
        oracle,
    )
    trials = {tuple(t["candidates"]): t for t in result["trials"]}
    assert trials[()]["verdict"] == HOLDS
    for single in (("switch",), ("port",)):
        assert trials[single]["verdict"] == UNKNOWN
        assert "L2 failure is not modeled" in trials[single]["evaluation"]["reason"]
    assert result["survives_all_single_failures"] is False


def test_routed_failure_with_an_l2_switch_present_is_decided(graph):
    net = _with_l2_switch()
    before = ev.answer(apply_failures(_network(), [{"kind": "device", "uid": A}]), _request())
    after = ev.answer(apply_failures(net, [{"kind": "device", "uid": A}]), _request())
    assert (after.lower, after.upper) == (before.lower, before.upper)
