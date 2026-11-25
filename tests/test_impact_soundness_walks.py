"""Routing and packet walks that check the bounds of impact verdicts."""

from dataclasses import replace

import pytest
from tests import test_impact_evaluate as estate
from tests.test_impact_evaluate import graph as graph
from tests.test_impact_sessions import Verdict, ips
from tests.test_simul_rib import (
    CTX,
    P1_SESSION,
    P2_SESSION,
    _connected,
    _ctx,
    _path,
    _process,
    _session,
    _static,
    _two_peer_input,
)

from hst.path.state import FlowRegion
from hst.simul import certainty, rib
from hst.simul.propagate import POST_IMPORT

ev = estate.ev
PREFIX = "203.0.113.0/24"
DOWNSTREAM = "vrf:downstream"


def _internal_estate():
    inp = _two_peer_input()
    inp.contexts.append(_ctx(DOWNSTREAM, "dev:downstream"))
    inp.connected.extend(
        [
            _connected("10.0.3.0/30", "Ethernet1/3"),
            _connected("10.0.3.0/30", "Ethernet1/1", DOWNSTREAM),
        ]
    )
    inp.bgp.processes.append(_process("rp:downstream", DOWNSTREAM, 65004, "10.255.0.4"))
    inp.bgp.sessions.extend(
        [
            _session("bgp:r1:downstream", "rp:r1:bgp", 65001, 65004, "10.0.3.1", "10.0.3.2"),
            _session("bgp:downstream:r1", "rp:downstream", 65004, 65001, "10.0.3.2", "10.0.3.1"),
        ]
    )
    inp.observed_paths.append(
        {
            **_path("bgp:downstream:r1", PREFIX, "10.0.3.1", as_path="65001 65002"),
            "context_uid": DOWNSTREAM,
            "device_uid": "dev:downstream",
        }
    )
    inp.direction_status[("bgp:downstream:r1", "received")] = "complete"
    return inp


def test_a_real_arrival_tie_never_proves_the_permitting_branch(graph):
    inp = estate._routing()
    inp.bgp.sessions[0].pop("import_policy_name")
    estate._firewall(graph, estate.B, "rb:b", [estate._deny(estate.APP)])
    for mode in ev.MODES:
        result = ev.answer(estate._network(inp), estate._request(), mode)
        assert result.lower == ()
        assert result.upper == estate.CLIENTS
        assert any(g["kind"] == rib.HISTORY_DEPENDENT for g in result.gaps)


def test_convergence_without_a_uniqueness_certificate_cannot_prove_no_route():
    inp = _internal_estate()
    net = ev.Network(inp, (), ev.GraphGates(None))
    assert not net.routes.model_errors
    assert net.routes.rounds < rib.MAX_ROUNDS
    assert {g["context_uid"] for g in net.routes.gaps if g["kind"] == certainty.UNIQUENESS} == {
        CTX,
        DOWNSTREAM,
    }
    # Even an absent prefix must retain a possible alternate stable outcome.
    assert net.incomplete(DOWNSTREAM, ips("198.51.100.10"))


@pytest.mark.parametrize("raw_seed", [False, True])
def test_withdrawals_supersede_internal_observations_and_their_dependents(raw_seed):
    inp = _internal_estate()
    if raw_seed:
        inp.observed_paths.pop()
        inp.bgp.seeds = [
            {
                "process_uid": "rp:downstream",
                "session_uid": "bgp:downstream:r1",
                "prefix": PREFIX,
                "next_hop": "10.0.3.1",
                "stage": POST_IMPORT,
                "as_path": [65001, 65002],
            }
        ]
        inp.bgp.observed_sessions = ["bgp:downstream:r1"]
    inp.static = [_static("198.51.100.0/24", "203.0.113.1", context_uid=DOWNSTREAM)]
    inp.bgp.local_routes = [
        {
            "process_uid": "rp:downstream",
            "prefix": "203.0.112.0/23",
            "intent": True,
            "origin_mechanism": "aggregate",
        }
    ]
    before = rib.compute(inp)
    expected = {PREFIX, "198.51.100.0/24", "203.0.112.0/23"}
    assert expected <= {r["prefix"] for r in before.rib if r["context_uid"] == DOWNSTREAM}
    changed = rib.shut_session(rib.shut_session(inp, P1_SESSION), P2_SESSION)
    after = rib.compute(changed, validate_observed=False)
    assert not expected & {r["prefix"] for r in after.rib if r["context_uid"] == DOWNSTREAM}
    assert DOWNSTREAM in changed.superseded_contexts
    assert len(inp.observed_paths) == (2 if raw_seed else 3)
    assert not inp.superseded_contexts
    assert all(s.get("state") != "shutdown" for s in inp.bgp.sessions)


def test_shutting_either_end_disables_both_directions():
    inp = _internal_estate()
    changed = rib.shut_session(inp, "bgp:r1:downstream")
    shut = {s["uid"] for s in changed.bgp.sessions if s.get("state") == "shutdown"}
    assert shut == {"bgp:r1:downstream", "bgp:downstream:r1"}
    assert not any(r["prefix"] == PREFIX and r["context_uid"] == DOWNSTREAM for r in rib.compute(changed).rib)


def test_invalidation_follows_observed_static_resolution_contexts():
    inp = _two_peer_input()
    inp.contexts.append(_ctx(DOWNSTREAM, "dev:downstream"))
    inp.observed_rib = {
        DOWNSTREAM: [
            {
                "prefix": "198.51.100.0/24",
                "protocol": "static",
                "next_hop": "203.0.113.1",
                "next_hop_context_uid": CTX,
            }
        ]
    }
    changed = rib.shut_session(inp, P1_SESSION)
    assert DOWNSTREAM in changed.superseded_contexts
    result = rib.compute(changed, validate_observed=False)
    assert any(
        g["kind"] == rib.NOT_OBSERVED and g["context_uid"] == DOWNSTREAM and g.get("scope") == "context"
        for g in result.gaps
    )


def test_complete_adj_rib_in_does_not_establish_external_response_to_a_change(graph):
    net = estate._network(estate._routing(fixed_boundary=False))
    result = ev.evaluate(net, estate._changes(estate.SHUT_A), estate._request())
    assert result.before.lower == estate.CLIENTS
    assert result.after.lower == ()
    assert result.after.upper == estate.CLIENTS
    assert not result.proven_loss and not result.proven_gain
    assert result.triage.worked_now_unknown == estate.CLIENTS
    assert any(g["kind"] == certainty.EXTERNAL_RESPONSE for g in result.after.gaps)


def test_a_fixed_boundary_assumption_is_explicit_and_returned(graph):
    result = ev.evaluate(estate._network(), estate._changes(estate.SHUT_A), estate._request())
    assert result.after.lower == estate.CLIENTS
    assert f"external advertisements remain fixed on session {estate.SESSION_B}" in result.after.assumptions


@pytest.mark.parametrize("capture", ["accepted", "missing-completeness"])
def test_selected_or_incompletely_captured_routes_cannot_prove_bounds(graph, capture):
    inp = estate._routing()
    if capture == "accepted":
        for row in inp.observed_paths:
            row["direction"] = "accepted"
        inp.direction_status = {
            (s["uid"], direction): "complete" if direction == "accepted" else "not-captured"
            for s in inp.bgp.sessions
            for direction in ("received", "accepted")
        }
    else:
        inp.direction_status = {}
    result = ev.answer(estate._network(inp), estate._request())
    assert result.lower == () and result.upper == estate.CLIENTS
    assert any(g["kind"] == rib.NOT_OBSERVED for g in result.gaps)


@pytest.mark.parametrize("condition", [ev.any_one, lambda *parts: ev.n_of_m(1, *parts), ev.every])
@pytest.mark.parametrize("mode", sorted(ev.MODES))
def test_equal_cost_choices_are_quantified_by_the_mode_and_the_assumption_is_stated(graph, condition, mode):
    """The selection for each connection over equal-cost paths is independent (`SPREAD_ASSUMPTION`)."""
    members = (ev.Member("a", ips("203.0.113.10")), ev.Member("b", ips("203.0.113.11")))
    request = estate._request(members=members, condition=condition(ev.member("a"), ev.member("b")))
    inp = estate._routing(
        bgp=False,
        static=[
            estate._static(PREFIX, "10.0.1.2"),
            estate._static(PREFIX, "10.0.2.2"),
        ],
    )
    estate._firewall(graph, estate.A, "rb:a", [estate._deny("203.0.113.11")])
    estate._firewall(graph, estate.B, "rb:b", [estate._deny("203.0.113.10")])
    result = ev.answer(estate._network(inp), request, mode)
    if mode == ev.POSSIBLE:
        assert result.lower == estate.CLIENTS
    else:
        assert result.upper == ()
    assert ev.SPREAD_ASSUMPTION in result.assumptions
    assert all(
        any(s.kind == "split" and s.device_uid == estate.R1 for s in e.steps)
        for m in result.members.values()
        for e in m.explanations
    )
    assert not any(
        s.kind in ("correlation-unobserved", "ambiguous")
        for m in result.members.values()
        for e in m.explanations
        for s in e.steps
    )


@pytest.mark.parametrize("negate", [False, True])
@pytest.mark.parametrize("action", ["accept", "drop"])
def test_opaque_first_match_and_its_complement_preserve_both_bounds(graph, negate, action):
    rule = estate._rule(
        action=action,
        src_any=False,
        src_obj_count=1,
        src_opaque=True,
        src_negate=negate,
        src_opaque_reasons=["identity not recorded"],
    )
    later = estate._rule(uid="later", pos=2, action="drop" if action == "accept" else "accept")
    estate._firewall(graph, estate.A, "rb:a", [rule, later])
    result = ev.answer(estate._network(), estate._request())
    assert result.lower == () and result.upper == estate.CLIENTS
    assert any(e.missing for e in result.members["app"].explanations)


def test_state_policy_at_another_location_must_allow_for_missing_synchronization():
    region = FlowRegion.from_query(ips("10.0.0.1"), ips("203.0.113.1"), frozenset({6}))
    transition = ev._UnlocatedStateFilter(Verdict("deny"), Verdict("permit"))
    outputs = transition.apply(region)
    assert len(outputs) == 1 and outputs[0][1].kind == "indeterminate"
    assert "synchronization" in outputs[0][1].reason
    assert ev._UnlocatedStateFilter(Verdict("deny"), Verdict("deny")).apply(region)[0][1].kind == "deny"


def test_a_binding_cannot_be_replayed_in_another_context_on_the_same_device():
    before = next(iter(FlowRegion.from_query(ips("10.0.0.1"), ips("203.0.113.1"), frozenset({6}))))
    after = before.narrow(src=ips("192.0.2.1"))
    mapping = ev._Rewrite("fw", "snat", before, after, context_uid="tenant:a")
    branch = ev._Branch(
        ev._reverse(after),
        before,
        frozenset({"dst"}),
        "fw",
        "tenant:b",
        None,
        0,
        frozenset(),
        (),
        phase="reply",
        translations=(mapping,),
    )
    walk = ev._Walk(ev.Network(rib.RibInput(), (), ev.GraphGates(None)), ev.POSSIBLE, "app")
    assert walk.undo(branch, "snat").rect == branch.rect
    restored = walk.undo(replace(branch, context_uid="tenant:a"), "snat")
    assert restored.rect.dst == before.src


def test_asymmetric_nat_state_is_unknown_before_no_route_can_be_proven():
    before = next(iter(FlowRegion.from_query(ips("10.0.0.1"), ips("203.0.113.1"), frozenset({6}))))
    after = before.narrow(src=ips("192.0.2.1"))
    mapping = ev._Rewrite("fw:a", "snat", before, after, context_uid="tenant:a")
    branch = ev._Branch(
        ev._reverse(after),
        before,
        frozenset({"dst"}),
        "fw:b",
        "tenant:b",
        None,
        0,
        frozenset(),
        (),
        phase="reply",
        translations=(mapping,),
        forward_devices=frozenset({("fw:a", "tenant:a")}),
    )
    walk = ev._Walk(ev.Network(rib.RibInput(), (), ev.GraphGates(None)), ev.GUARANTEED, "app")
    result = walk.device_pipeline(branch)
    assert not result.proven and not result.failed
    assert result.unknown == FlowRegion.single(before)
    assert result.explanations[0].steps[-1].kind == "state-location-unobserved"


def test_known_router_ids_are_deterministic_but_missing_ids_are_not():
    from hst.simul.bestpath import best_path_with_tie
    from hst.simul.route import Route

    first = Route(prefix=PREFIX, protocol="ibgp", originator_ip="10.0.0.1", next_hop="10.0.1.2")
    second = Route(prefix=PREFIX, protocol="ibgp", originator_ip="10.0.0.2", next_hop="10.0.2.2")
    assert best_path_with_tie([first, second]) == (first, False)
    assert best_path_with_tie([second, first]) == (first, False)
    assert best_path_with_tie([first.with_(originator_ip=None), second.with_(originator_ip=None)])[1]
