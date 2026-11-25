"""`hst.impact.evaluate` on an estate that loses a BGP peer."""

import importlib
import random

import pytest
from tests.test_path_nat import _dnat_row, _nat_row
from tests.test_path_trace import FakeGraph, _lb_member, _lb_vs, _rule

from hst import path
from hst.path.addrsets import _intervals, _ports, _subtract
from hst.path.state import FlowRegion
from hst.path.verdict import INDETERMINATE
from hst.simul import rib
from hst.simul.fw_overlay import Catalog, ChangeSet, parse_intents
from hst.simul.propagate import SimulationInput

# `hst.impact.evaluate` the module, not the `evaluate` function the package
# re-exports under the same name.
ev = importlib.import_module("hst.impact.evaluate")

TCP = frozenset({6})
CLIENTS = tuple(_intervals(["10.0.0.0/24"]))
APP = "203.0.113.10"
R1, A, B = "dev:r1", "dev:a", "dev:b"
VRF_R1, VRF_A, VRF_B = "vrf:r1", "vrf:a", "vrf:b"
SESSION_A, SESSION_B = "bgp:r1:a", "bgp:r1:b"
SHUT_A = {"kind": "bgp_session.shut", "params": {"session": SESSION_A}}

LP_200 = {
    "name": "RM_A_IN",
    "kind": "route-map",
    "entries": [{"seq": 10, "kind": "clause", "action": "permit", "set_local_pref": 200}],
}


# --- the scripted graph ------------------------------------------------------------------


class Graph(FakeGraph):
    def __init__(self):
        super().__init__()
        self.rb_by_dev: dict[str, dict] = {}
        self.rules_by_rb: dict[str, list[dict]] = {}

    def read(self, query, **params):
        dev = params.get("dev")
        if dev is not None and "rb" not in params:
            self.rb = self.rb_by_dev.get(dev)
        if "FwRulebase {uid: $rb}" in query:
            return list(self.rules_by_rb.get(params.get("rb"), []))
        return super().read(query, **params)


@pytest.fixture()
def graph(monkeypatch):
    g = Graph()

    def read(session, query, **params):
        rows = g.read(query, **params)
        overlay = getattr(session, "overlay", None)
        return rows if overlay is None else overlay(query, params, rows)

    monkeypatch.setattr(path, "_read", read)
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    return g


# --- the estate ---------------------------------------------------------------------------


def _ivals(*specs):
    return tuple(_intervals(list(specs)))


def _pts(spec):
    return tuple(_ports(spec))


def _interfaces(vip=None):
    b_eth1 = ("203.0.113.2",) + ((vip,) if vip else ())
    return (
        ev.Interface(R1, "if:r1-eth0", "eth0", VRF_R1, ("10.0.0.0/24",), ("10.0.0.1",)),
        ev.Interface(R1, "if:r1-eth1", "eth1", VRF_R1, ("10.0.1.0/30",), ("10.0.1.1",)),
        ev.Interface(R1, "if:r1-eth2", "eth2", VRF_R1, ("10.0.2.0/30",), ("10.0.2.1",)),
        ev.Interface(A, "if:a-eth0", "eth0", VRF_A, ("10.0.1.0/30",), ("10.0.1.2",)),
        ev.Interface(A, "if:a-eth1", "eth1", VRF_A, ("203.0.113.0/24",), ("203.0.113.1",)),
        ev.Interface(B, "if:b-eth0", "eth0", VRF_B, ("10.0.2.0/30",), ("10.0.2.2",)),
        ev.Interface(B, "if:b-eth1", "eth1", VRF_B, ("203.0.113.0/24",), b_eth1),
    )


def _ctx(uid, device_uid):
    return {"uid": uid, "device_uid": device_uid, "name": "default", "platform": "nxos"}


def _connected(context_uid, prefix, interface):
    return {"context_uid": context_uid, "prefix": prefix, "interface": interface}


def _static(prefix, next_hop, context_uid=VRF_R1):
    return {
        "context_uid": context_uid,
        "prefix": prefix,
        "next_hop": next_hop,
        "interface": None,
        "next_hop_context_uid": None,
        "discard": None,
    }


def _session(uid, peer_asn, local_ip, peer_ip, **kwargs):
    return {
        "uid": uid,
        "process_uid": "rp:r1",
        "local_asn": 65001,
        "peer_asn": peer_asn,
        "local_ip": local_ip,
        "peer_ip": peer_ip,
        **kwargs,
    }


def _path(session_uid, prefix, next_hop, as_path):
    return {
        "device_uid": R1,
        "context_uid": VRF_R1,
        "session_uid": session_uid,
        "peer_ip": next_hop,
        "af": 4,
        "safi": "unicast",
        "direction": "received",
        "rib_type": "adj-rib-in",
        "policy_stage": "pre-import",
        "path_id": None,
        "prefix": prefix,
        "prefixlen": 24,
        "next_hop": next_hop,
        "next_hop_context_uid": None,
        "as_path": as_path,
        "local_pref": 100,
        "med": None,
        "origin": "igp",
        "communities": None,
        "best": None,
    }


def _routing(*, b_next_hop="10.0.2.2", b_observed=True, bgp=True, static=(), fixed_boundary=True):
    contexts = [_ctx(VRF_R1, R1), _ctx(VRF_A, A), _ctx(VRF_B, B)]
    connected = [
        _connected(VRF_R1, "10.0.0.0/24", "eth0"),
        _connected(VRF_R1, "10.0.1.0/30", "eth1"),
        _connected(VRF_R1, "10.0.2.0/30", "eth2"),
        _connected(VRF_A, "10.0.1.0/30", "eth0"),
        _connected(VRF_A, "203.0.113.0/24", "eth1"),
        _connected(VRF_B, "10.0.2.0/30", "eth0"),
        _connected(VRF_B, "203.0.113.0/24", "eth1"),
    ]
    if not bgp:
        return rib.RibInput(contexts=contexts, connected=connected, static=list(static), platform="nxos")
    process = {
        "uid": "rp:r1",
        "context_uid": VRF_R1,
        "proto": "bgp",
        "asn": 65001,
        "router_id": "10.255.0.1",
        "platform": "nxos",
    }
    sessions = [
        _session(
            SESSION_A,
            65002,
            "10.0.1.1",
            "10.0.1.2",
            import_policy_name="RM_A_IN",
            import_policy_kind="route-map",
        ),
        _session(SESSION_B, 65003, "10.0.2.1", "10.0.2.2"),
    ]
    paths = [_path(SESSION_A, "203.0.113.0/24", "10.0.1.2", "65002")]
    if b_observed:
        paths.append(_path(SESSION_B, "203.0.113.0/24", b_next_hop, "65003"))
    status = {
        (SESSION_A, "received"): "complete",
        (SESSION_A, "accepted"): "not-captured",
        (SESSION_B, "received"): "complete" if b_observed else "not-captured",
        (SESSION_B, "accepted"): "not-captured",
    }
    return rib.RibInput(
        contexts=contexts,
        connected=connected,
        static=list(static),
        bgp=SimulationInput(processes=[process], sessions=sessions, policies=[LP_200]),
        observed_paths=paths,
        direction_status=status,
        # This estate defines the whole, invariant supply of both peers.
        fixed_external_sessions=frozenset({SESSION_A, SESSION_B}) if fixed_boundary else frozenset(),
        platform="nxos",
    )


def _network(routing=None, interfaces=None):
    interfaces = interfaces or _interfaces()
    # every context of the estate is in one routing domain
    domains = {i.context_uid: frozenset({"declared:estate"}) for i in interfaces if i.context_uid}
    return ev.Network(routing or _routing(), interfaces, ev.GraphGates(session=None), context_domains=domains)


def _request(dst=APP, port="443", proto=TCP, sources=CLIENTS, members=None, condition=None):
    members = members or (ev.Member("app", _ivals(dst)),)
    return ev.RequestSet(
        "the application",
        sources,
        "app",
        members,
        condition or ev.member(members[0].name),
        ev.Service(proto, None if port is None else _pts(port)),
    )


def _changes(*intents):
    catalog = Catalog()
    return ChangeSet(intents=parse_intents(list(intents), catalog), catalog=catalog)


def _deny_intent(rulebase, destination, **params):
    return {
        "kind": "fw_rule.add",
        "params": {
            "rulebase": rulebase,
            "position": 1,
            "action": "drop",
            "source": "any",
            "destination": [destination],
            **params,
        },
    }


def _rb(uid, default_action="accept"):
    return {
        "rb_uid": uid,
        "rb_name": uid,
        "vendor": "checkpoint",
        "default_action": default_action,
        "approximate": False,
    }


def _deny(dst, uid="cp:deny", action="drop", port="443", **kw):
    return _rule(
        uid=uid,
        pos=1,
        action=action,
        dst_any=False,
        dst_cidrs=[f"{dst}/32"],
        svc_any=False,
        protos=["tcp"],
        ports=[port],
        **kw,
    )


def _firewall(graph, device_uid, uid, rules, default_action="accept"):
    graph.rb_by_dev[device_uid] = _rb(uid, default_action)
    graph.rules_by_rb[uid] = rules


def _only(answer, name="app"):
    """The one explanation of a member, when there is one."""
    explanations = answer.members[name].explanations
    assert len(explanations) == 1, [(e.outcome, [s.kind for s in e.steps]) for e in explanations]
    return explanations[0]


def _step(explanation, stage, kind=None, device=None):
    """The last step of a stage (and kind, and device) on an explanation."""
    steps = [
        s
        for s in explanation.steps
        if s.stage == stage
        and (kind is None or s.kind == kind)
        and (device is None or s.device_uid == device)
    ]
    assert steps, [(s.device_uid, s.stage, s.kind, s.detail) for s in explanation.steps]
    return steps[-1]


def _subset(lower, upper):
    return not _subtract(list(lower), list(upper))


# --- losing a BGP peer ---------------------------------------------------------------------


class TestLosingABgpPeer:
    def test_the_baseline_selects_peer_a_and_proves_the_request(self, graph):
        before = ev.answer(_network(), _request())
        assert before.lower == CLIENTS
        assert before.upper == CLIENTS
        member = before.members["app"]
        assert member.lower == member.request
        assert member.upper == member.request
        explanation = _only(before)
        assert explanation.outcome == ev.HOLDS
        assert "via 10.0.1.2" in _step(explanation, "route", "via", R1).detail
        assert _step(explanation, "route", "select", R1).data == {"routes": 1, "advertisements": 2}
        assert _step(explanation, "route", "select", A).data == {"routes": 1}
        assert [s.device_uid for s in explanation.steps if s.stage == "forwarding"] == [A]
        assert before.gaps == ()

    def test_b_works_with_reduced_redundancy(self, graph):
        impact = ev.evaluate(_network(), _changes(SHUT_A), _request())
        assert impact.proven_loss == ()
        assert impact.possible_loss == ()
        assert impact.proven_gain == ()
        assert impact.possible_gain == ()
        after = _only(impact.after)
        assert after.outcome == ev.HOLDS
        assert "via 10.0.2.2" in _step(after, "route", "via", R1).detail
        assert [s.device_uid for s in after.steps if s.stage == "forwarding"] == [B]
        # the request still holds, through the one advertisement that is left
        assert _step(_only(impact.before), "route", "select", R1).data["advertisements"] == 2
        assert _step(after, "route", "select", R1).data["advertisements"] == 1

    def test_b_is_selected_but_a_downstream_firewall_blocks(self, graph):
        _firewall(graph, B, "rb:b", [_deny(APP)])
        impact = ev.evaluate(_network(), _changes(SHUT_A), _request())
        assert impact.proven_loss == CLIENTS
        assert impact.possible_loss == CLIENTS
        assert impact.possible_gain == ()
        member = impact.members["app"]
        assert member.proven_loss == impact.before.members["app"].request
        after = _only(impact.after)
        assert after.outcome == ev.FAILS
        assert "via 10.0.2.2" in _step(after, "route", "via", R1).detail
        blocked = _step(after, "filter", "deny")
        assert blocked.device_uid == B
        assert impact.after.members["app"].upper.is_empty()
        # the differences carry the traces on both sides
        before_traces, after_traces = impact.explain("app", member.proven_loss)
        assert [e.outcome for e in before_traces] == [ev.HOLDS]
        assert [e.outcome for e in after_traces] == [ev.FAILS]

    def test_bs_next_hop_cannot_resolve(self, graph):
        impact = ev.evaluate(_network(_routing(b_next_hop="10.77.0.1")), _changes(SHUT_A), _request())
        assert impact.proven_loss == CLIENTS
        assert impact.possible_loss == CLIENTS
        after = _only(impact.after)
        assert after.outcome == ev.FAILS
        assert after.steps[-1].kind == "no-route"
        assert after.steps[-1].device_uid == R1
        assert [(g["kind"], g["prefix"], g["next_hop"]) for g in impact.after.gaps] == [
            ("unresolved-next-hop", "203.0.113.0/24", "10.77.0.1")
        ]
        assert _only(impact.before).outcome == ev.HOLDS

    def test_bs_routes_are_not_observed_so_the_impact_is_unknown(self, graph):
        impact = ev.evaluate(_network(_routing(b_observed=False)), _changes(SHUT_A), _request())
        assert impact.proven_loss == ()
        assert impact.possible_loss == CLIENTS
        assert impact.after.lower == ()
        assert impact.after.upper == CLIENTS
        after = _only(impact.after)
        assert after.outcome == ev.NOT_ESTABLISHED
        assert after.steps[-1].kind == "incomplete"
        # the missing input is named by its peer (the gap keeps the session uid)
        assert any(f"BGP peer 10.0.2.2 on {R1}:" in line for line in after.missing)
        assert [g["session_uid"] for g in impact.before.gaps] == [SESSION_B]
        # the input is missing before the change too
        assert impact.before.lower == ()
        assert impact.before.upper == CLIENTS
        assert _only(impact.before).outcome == ev.NOT_ESTABLISHED
        assert [g["kind"] for g in impact.before.gaps] == ["not-observed"]


# --- the bounds ----------------------------------------------------------------------------


class TestBounds:
    def test_lower_is_a_subset_of_upper_before_and_after_over_random_estates(self, graph):
        rng = random.Random(9)
        actions = ["accept", "drop", "inspect", None]
        for _ in range(40):
            for device_uid, uid in ((A, "rb:a"), (B, "rb:b")):
                action = rng.choice(actions)
                graph.rb_by_dev.pop(device_uid, None)
                if action is not None:
                    _firewall(
                        graph, device_uid, uid, [_deny(APP, action=action)], rng.choice(["accept", "drop"])
                    )
            routing = _routing(
                b_next_hop=rng.choice(["10.0.2.2", "10.77.0.1"]),
                b_observed=rng.choice([True, False]),
            )
            mode = rng.choice(ev.MODES)
            request = _request(port=rng.choice(["443", "1-1024", None]), proto=rng.choice([TCP, None]))
            impact = ev.evaluate(_network(routing), _changes(SHUT_A), request, mode)
            for answer in (impact.before, impact.after):
                assert _subset(answer.lower, answer.upper)
                assert _subset(answer.upper, CLIENTS)
                member = answer.members["app"]
                assert member.lower.subtract(member.upper).is_empty()
                assert member.upper.subtract(member.request).is_empty()
                # every part of the request is explained, and only once
                covered = FlowRegion()
                for explanation in member.explanations:
                    part = FlowRegion.single(explanation.request)
                    covered = covered.union(part)
                assert member.request.subtract(covered).is_empty()
                for explanation in member.explanations:
                    assert explanation.outcome in (ev.HOLDS, ev.FAILS, ev.NOT_ESTABLISHED)
                    assert (explanation.outcome == ev.NOT_ESTABLISHED) == bool(explanation.missing)
            assert _subset(impact.proven_loss, impact.possible_loss)
            assert _subset(impact.proven_gain, impact.possible_gain)

    def test_removing_evidence_never_narrows_the_bounds(self, graph):
        """With one fact removed, the lower bound can only shrink and the upper bound can only expand."""
        rng = random.Random(3)
        for _ in range(30):
            for device_uid, uid in ((A, "rb:a"), (B, "rb:b")):
                action = rng.choice(["accept", "drop", "inspect", None])
                graph.rb_by_dev.pop(device_uid, None)
                if action is not None:
                    _firewall(
                        graph, device_uid, uid, [_deny(APP, action=action)], rng.choice(["accept", "drop"])
                    )
            next_hop = rng.choice(["10.0.2.2", "10.77.0.1"])
            request = _request(port=rng.choice(["443", "1-1024", None]), proto=rng.choice([TCP, None]))
            for mode in ev.MODES:
                full = ev.answer(_network(_routing(b_next_hop=next_hop, b_observed=True)), request, mode)
                less = ev.answer(_network(_routing(b_next_hop=next_hop, b_observed=False)), request, mode)
                assert _subset(less.lower, full.lower), (mode, "the lower bound grew on less evidence")
                assert _subset(full.upper, less.upper), (mode, "the upper bound shrank on less evidence")

    def test_the_same_mode_and_condition_on_both_sides(self, graph):
        net = _network()
        possible = ev.answer(net, _request(), ev.POSSIBLE)
        guaranteed = ev.answer(net, _request(), ev.GUARANTEED)
        with pytest.raises(ValueError, match="mode"):
            ev.compare(possible, guaranteed)
        other = ev.answer(net, _request(port="80"))
        with pytest.raises(ValueError, match="request set"):
            ev.compare(possible, other)
        impact = ev.evaluate(net, _changes(SHUT_A), _request(), ev.GUARANTEED)
        assert impact.mode == impact.before.mode == impact.after.mode == ev.GUARANTEED
        assert impact.before.request_set == impact.after.request_set
        with pytest.raises(ValueError, match="mode"):
            ev.answer(net, _request(), "likely")

    def test_results_are_deterministic_over_shuffled_inputs(self, graph):
        _firewall(graph, B, "rb:b", [_deny(APP)])
        reference = {mode: ev.evaluate(_network(), _changes(SHUT_A), _request(), mode) for mode in ev.MODES}
        for seed in range(6):
            rng = random.Random(seed)
            routing = _routing()
            interfaces = list(_interfaces())
            rng.shuffle(interfaces)
            for rows in (routing.contexts, routing.connected, routing.observed_paths, routing.bgp.sessions):
                rng.shuffle(rows)
            net = _network(routing, tuple(interfaces))
            for mode in ev.MODES:
                assert ev.evaluate(net, _changes(SHUT_A), _request(), mode) == reference[mode]


# --- unknown gates and missing transitions -------------------------------------------------


class TestUnknownAndMissing:
    def test_an_unknown_gate_keeps_the_request_in_the_upper_set_only(self, graph):
        _firewall(graph, B, "rb:b", [_deny(APP, action="inspect")])
        routing = _routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.2")])
        before = ev.answer(_network(routing), _request())
        assert before.lower == ()
        assert before.upper == CLIENTS
        member = before.members["app"]
        assert member.lower.is_empty()
        assert member.upper == member.request
        explanation = _only(before)
        assert explanation.outcome == ev.NOT_ESTABLISHED
        assert _step(explanation, "filter").kind == INDETERMINATE
        assert explanation.missing
        assert explanation.steps[-1].device_uid == B

    def test_an_unstated_dimension_a_gate_reads_is_not_established(self, graph):
        _firewall(graph, B, "rb:b", [_deny(APP)], "drop")
        routing = _routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.2")])
        before = ev.answer(_network(routing), _request(port=None, proto=None))
        explanation = _only(before)
        assert explanation.outcome == ev.NOT_ESTABLISHED
        assert explanation.steps[-1].unknown
        assert before.lower == ()
        assert before.upper == CLIENTS

    def test_a_missing_transition_never_removes_a_request_from_the_upper_set(self, graph):
        # a next hop that resolves on R1's connected prefix but that no
        # interface in the model holds: the flow leaves the model
        routing = _routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.3")])
        before = ev.answer(_network(routing), _request())
        assert before.lower == ()
        assert before.upper == CLIENTS
        explanation = _only(before)
        assert explanation.outcome == ev.NOT_ESTABLISHED
        assert explanation.steps[-1].kind == "unowned"
        assert "10.0.2.3" in explanation.missing[0]
        # a source population no interface serves
        outside = ev.answer(_network(), _request(sources=_ivals("172.16.0.0/24")))
        assert outside.lower == ()
        assert outside.upper == _ivals("172.16.0.0/24")
        assert _only(outside).steps[-1].kind == "unattached"
        # a context the routing calculation did not cover
        partial = _routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.2")])
        partial.contexts = [c for c in partial.contexts if c["uid"] != VRF_B]
        partial.connected = [c for c in partial.connected if c["context_uid"] != VRF_B]
        uncovered = ev.answer(_network(partial), _request())
        assert uncovered.lower == ()
        assert uncovered.upper == CLIENTS
        assert _only(uncovered).steps[-1].kind == "not-computed"

    @pytest.mark.parametrize("translation", ["203.0.113.0/28", "203.0.113.0/27"])
    def test_translated_address_predicates_require_a_deterministic_mapping(self, graph, translation):
        # Equal-sized networks map by offset; a larger output pool does not
        # identify which original request reaches the denied address.
        graph.nat_by_dev[R1] = [
            _dnat_row(
                orig_dst_raw="198.51.100.0/28",
                orig_dst_addrs=["198.51.100.0/28"],
                translation=translation,
                xlate_dst_addrs=[translation],
            )
        ]
        _firewall(graph, B, "rb:b", [_deny("203.0.113.5")])
        routing = _routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.2")])
        before = ev.answer(_network(routing), _request(dst="198.51.100.0/28"))
        member = before.members["app"]
        if translation.endswith("/27"):
            assert member.lower.is_empty()
            assert member.upper == member.request
            assert {e.outcome for e in member.explanations} == {ev.NOT_ESTABLISHED}
            assert all("deterministic mapping" in e.missing[0] for e in member.explanations)
        else:
            denied = FlowRegion.from_query(CLIENTS, _ivals("198.51.100.5"), TCP, _pts("443"))
            expected = member.request.subtract(denied)
            for bound in (member.lower, member.upper):
                assert not bound.subtract(expected)
                assert not expected.subtract(bound), [e.missing for e in member.explanations]
            assert {e.outcome for e in member.explanations} == {ev.HOLDS, ev.FAILS}


# --- the two modes -------------------------------------------------------------------------


class TestModes:
    def test_possible_needs_one_successor_and_guaranteed_needs_every_one(self, graph):
        _firewall(graph, B, "rb:b", [_deny(APP)])
        routing = _routing(
            bgp=False,
            static=[_static("203.0.113.0/24", "10.0.1.2"), _static("203.0.113.0/24", "10.0.2.2")],
        )
        net = _network(routing)
        possible = ev.answer(net, _request(), ev.POSSIBLE)
        assert possible.lower == CLIENTS
        assert possible.upper == CLIENTS
        guaranteed = ev.answer(net, _request(), ev.GUARANTEED)
        assert guaranteed.lower == ()
        assert guaranteed.upper == ()
        for answer in (possible, guaranteed):
            outcomes = sorted(e.outcome for e in answer.members["app"].explanations)
            assert outcomes == [ev.FAILS, ev.HOLDS]
            assert {
                _step(e, "route", "select", R1).data["routes"] for e in answer.members["app"].explanations
            } == {2}

    def test_an_equal_cost_split_is_decided_under_the_mode_and_explained(self, graph):
        """Flows spread over equal-cost paths, so the paths are quantified by
        the mode, and the explanations of the
        split part carry a `split` step that names each path's outcome."""
        _firewall(graph, B, "rb:b", [_deny(APP)])
        routing = _routing(
            bgp=False,
            static=[_static("203.0.113.0/24", "10.0.1.2"), _static("203.0.113.0/24", "10.0.2.2")],
        )
        net = _network(routing)
        request = _request()
        possible = ev.answer(net, request, ev.POSSIBLE)
        assert possible.lower == CLIENTS
        guaranteed = ev.answer(net, request, ev.GUARANTEED)
        assert guaranteed.upper == ()
        for answer in (possible, guaranteed):
            assert ev.SPREAD_ASSUMPTION in answer.assumptions
            explanations = answer.members["app"].explanations
            assert sorted(e.outcome for e in explanations) == [ev.FAILS, ev.HOLDS]
            for explanation in explanations:
                split = _step(explanation, "route", "split", R1)
                assert split.data == {"paths": 2}
                assert split.detail.startswith(f"split by path at {R1}: ")
                assert "via 203.0.113.0/24 via 10.0.1.2: passes" in split.detail
                assert "via 203.0.113.0/24 via 10.0.2.2: fails, deny" in split.detail
                assert split.detail.endswith(f"Which path a flow takes depends on the hash on {R1}")
                # the split step sits before the path's own route step
                steps = list(explanation.steps)
                assert steps.index(split) < steps.index(_step(explanation, "route", "via", R1))
            assert not any(s.kind == "ambiguous" for e in explanations for s in e.steps)

    def test_an_equal_cost_path_open_for_missing_data_keeps_its_own_reason(self, graph):
        # one path answers, the other leaves the model at a next hop no
        # interface holds: not a split, so no split step and no ambiguity
        _firewall(graph, B, "rb:b", [])
        routing = _routing(
            bgp=False,
            static=[_static("203.0.113.0/24", "10.0.1.2"), _static("203.0.113.0/24", "10.0.2.3")],
        )
        net = _network(routing)
        request = _request()
        possible = ev.answer(net, request, ev.POSSIBLE)
        assert possible.lower == CLIENTS
        guaranteed = ev.answer(net, request, ev.GUARANTEED)
        assert guaranteed.lower == () and guaranteed.upper == CLIENTS
        open_parts = [e for e in guaranteed.members["app"].explanations if e.outcome == ev.NOT_ESTABLISHED]
        assert open_parts and all("10.0.2.3" in e.missing[0] for e in open_parts)
        assert not any(
            s.kind in ("split", "ambiguous") for e in guaranteed.members["app"].explanations for s in e.steps
        )

    def test_the_mode_decides_what_an_ecmp_loss_is(self, graph):
        routing = _routing(
            bgp=False,
            static=[_static("203.0.113.0/24", "10.0.1.2"), _static("203.0.113.0/24", "10.0.2.2")],
        )
        _firewall(graph, B, "rb:b", [])
        delta = _changes(_deny_intent("rb:b", APP))
        possible = ev.evaluate(_network(routing), delta, _request(), ev.POSSIBLE)
        assert possible.proven_loss == ()
        assert possible.possible_loss == ()
        guaranteed = ev.evaluate(_network(routing), delta, _request(), ev.GUARANTEED)
        assert guaranteed.proven_loss == CLIENTS


# --- ownership ambiguity -------------------------------------------------------------------


class TestAmbiguousOwners:
    """`_choose` in `unspecified` mode: the rule for alternatives that are a
    gap in the data, not a spread of traffic."""

    def _result(self, rect, outcome):
        region = FlowRegion.single(rect)
        step = (ev.Step("dev:x", "filter", "permit" if outcome == ev.HOLDS else "deny", "rule 1"),)
        missing = () if outcome != ev.NOT_ESTABLISHED else ("x",)
        explanation = ev.Explanation("app", rect, outcome, step, missing)
        if outcome == ev.HOLDS:
            return ev._Result(proven=region, explanations=(explanation,))
        if outcome == ev.FAILS:
            return ev._Result(failed=region, explanations=(explanation,))
        return ev._Result(unknown=region, explanations=(explanation,))

    def test_owners_that_decide_differently_leave_the_part_open_and_name_the_ambiguity(self):
        rect = _request().member_region(_request().members[0]).rects[0]
        result = ev._choose(
            "unspecified",
            rect,
            [self._result(rect, ev.HOLDS), self._result(rect, ev.FAILS)],
            subject="203.0.113.10 is owned by eth1 on dev:a, eth1 on dev:b",
        )
        assert result.proven.is_empty() and result.failed.is_empty()
        assert result.unknown == FlowRegion.single(rect)
        ambiguous = [e for e in result.explanations if any(s.kind == "ambiguous" for s in e.steps)]
        assert len(ambiguous) == 1
        assert ambiguous[0].outcome == ev.NOT_ESTABLISHED
        assert ambiguous[0].missing == (
            "203.0.113.10 is owned by eth1 on dev:a, eth1 on dev:b, and they decide the flow differently; "
            "which one handles it is not recorded",
        )

    def test_a_part_an_owner_left_open_keeps_that_owners_reason(self):
        rect = _request().member_region(_request().members[0]).rects[0]
        result = ev._choose(
            "unspecified",
            rect,
            [self._result(rect, ev.HOLDS), self._result(rect, ev.NOT_ESTABLISHED)],
            subject="203.0.113.10 is owned by eth1 on dev:a, eth1 on dev:b",
        )
        assert result.unknown == FlowRegion.single(rect)
        assert not any(s.kind == "ambiguous" for e in result.explanations for s in e.steps)
        assert [e.missing for e in result.explanations if e.outcome == ev.NOT_ESTABLISHED] == [("x",)]


# --- the request identity ----------------------------------------------------------------


class TestRequestIdentity:
    def test_the_request_identity_survives_destination_nat(self, graph):
        public = "198.51.100.10"
        graph.nat_by_dev[R1] = [
            _dnat_row(orig_dst_raw=public, orig_dst_addrs=[public], translation=APP, xlate_dst_addrs=[APP])
        ]
        _firewall(graph, B, "rb:b", [_deny(APP)])
        impact = ev.evaluate(_network(), _changes(SHUT_A), _request(dst=public))
        assert impact.proven_loss == CLIENTS
        member = impact.members["app"]
        assert [r.dst for r in member.proven_loss] == [_ivals(public)]
        after = _only(impact.after)
        assert after.request.dst == _ivals(public)
        assert _step(after, "dnat", "rewrite").device_uid == R1
        assert _step(after, "filter", "deny").device_uid == B
        before = _only(impact.before)
        assert before.outcome == ev.HOLDS
        assert before.request.dst == _ivals(public)

    def test_the_request_identity_survives_a_load_balancer_and_a_changed_member(self, graph):
        vip = "203.0.113.100"
        graph.vip[(vip, B)] = _lb_vs(uid="vs:web", name="web-443", ip_uid=f"ip:{vip}")
        graph.pool_members["vs:web"] = [
            _lb_member(uid="m:1", name="m1", ip="203.0.113.10", port=8443),
            _lb_member(uid="m:2", name="m2", ip="203.0.113.11", port=8443),
        ]
        _firewall(graph, B, "rb:b", [])
        # This policy checks backend headers after the VIP translation.
        graph.rb_by_dev[B]["vendor"] = "cisco"
        routing = _routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.2")])
        net = _network(routing, _interfaces(vip=vip))
        request = _request(dst=vip)
        before = ev.answer(net, request)
        assert before.lower == CLIENTS
        explanations = before.members["app"].explanations
        assert [e.outcome for e in explanations] == [ev.HOLDS, ev.HOLDS]
        # every explanation answers for the request the caller stated, not
        # for the member connection it was traced as
        for explanation in explanations:
            assert explanation.request.dst == _ivals(vip)
            assert explanation.request.dport == _pts("443")
            assert _step(explanation, "load-balancer", "relate").device_uid == B
        assert {_step(e, "load-balancer", "relate").detail for e in explanations} == {
            "web-443 relates the request to member 203.0.113.10",
            "web-443 relates the request to member 203.0.113.11",
        }
        # one member is denied: a changed selection is the same request
        delta = _changes(_deny_intent("rb:b", "203.0.113.11"))
        possible = ev.evaluate(net, delta, request, ev.POSSIBLE)
        assert possible.proven_loss == ()
        assert possible.possible_loss == ()
        assert sorted(e.outcome for e in possible.after.members["app"].explanations) == [ev.FAILS, ev.HOLDS]
        guaranteed = ev.evaluate(net, delta, request, ev.GUARANTEED)
        assert guaranteed.proven_loss == CLIENTS
        assert [r.dst for r in guaranteed.members["app"].proven_loss] == [_ivals(vip)]

    def test_a_vip_with_no_listener_fails_as_the_trace_blocks_it(self, graph):
        """The impact engine decides a known VIP miss as the path trace does
        (`test_path_trace`): a flow no VirtualService on the VIP serves stops
        at the VIP. A VirtualService of a kind the engine does not evaluate
        keeps the miss open."""
        vip = "203.0.113.100"
        graph.vip[(vip, B)] = _lb_vs(uid="vs:web", name="web-443", ip_uid=f"ip:{vip}")
        graph.pool_members["vs:web"] = [_lb_member(uid="m:1", name="m1", ip="203.0.113.10", port=8443)]
        _firewall(graph, B, "rb:b", [])
        routing = _routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.2")])
        net = _network(routing, _interfaces(vip=vip))

        answer = ev.answer(net, _request(dst=vip, port="80"))
        assert answer.upper == ()
        explanation = _only(answer)
        assert explanation.outcome == ev.FAILS
        stop = _step(explanation, "load-balancer", "deny")
        assert stop.device_uid == B
        assert stop.detail == (
            f"deny at VIP {vip} (no virtual service on this VIP serves the flow's protocol and port)"
        )

        graph.vip[(vip, B)] = [graph.vip[(vip, B)], _lb_vs(uid="vs:dns", name="dns", kind="gslb", port=53)]
        open_answer = ev.answer(net, _request(dst=vip, port="80"))
        assert open_answer.upper == CLIENTS and open_answer.lower == ()
        assert _only(open_answer).outcome == ev.NOT_ESTABLISHED


# --- the success condition -----------------------------------------------------------------


class TestCondition:
    def test_every_any_one_and_n_of_m_are_three_valued(self):
        h, f, u = ev.HOLDS, ev.FAILS, ev.NOT_ESTABLISHED
        m = ev.member
        outcomes = {"a": h, "b": f, "c": u}
        assert ev._evaluate(ev.every(m("a"), m("a")), outcomes) == h
        assert ev._evaluate(ev.every(m("a"), m("b")), outcomes) == f
        assert ev._evaluate(ev.every(m("a"), m("c")), outcomes) == u
        assert ev._evaluate(ev.any_one(m("b"), m("a")), outcomes) == h
        assert ev._evaluate(ev.any_one(m("b"), m("b")), outcomes) == f
        assert ev._evaluate(ev.any_one(m("b"), m("c")), outcomes) == u
        assert ev._evaluate(ev.n_of_m(2, m("a"), m("b"), m("c")), outcomes) == u
        assert ev._evaluate(ev.n_of_m(1, m("a"), m("b"), m("c")), outcomes) == h
        assert ev._evaluate(ev.n_of_m(2, m("a"), m("b"), m("b")), outcomes) == f
        nested = ev.every(m("a"), ev.any_one(m("b"), ev.n_of_m(1, m("c"), m("a"))))
        assert ev._evaluate(nested, outcomes) == h

    def test_a_request_set_refuses_a_malformed_condition(self):
        with pytest.raises(ValueError, match="lacks"):
            _request(condition=ev.member("dns"))
        with pytest.raises(ValueError, match="n between"):
            _request(condition=ev.n_of_m(2, ev.member("app")))
        with pytest.raises(ValueError, match="at least one part"):
            _request(condition=ev.every())
        with pytest.raises(ValueError, match="address family"):
            _request(sources=_ivals("2001:db8::/64"))

    def test_the_condition_composes_the_members_of_an_application(self, graph):
        members = (
            ev.Member("dns", _ivals("203.0.113.53"), ev.Service(frozenset({17}), _pts("53"))),
            ev.Member("auth", _ivals("203.0.113.20")),
            ev.Member("be1", _ivals("203.0.113.31")),
            ev.Member("be2", _ivals("203.0.113.32")),
            ev.Member("be3", _ivals("203.0.113.33")),
        )
        m = ev.member
        condition = ev.every(m("dns"), m("auth"), ev.n_of_m(2, m("be1"), m("be2"), m("be3")))
        request = _request(members=members, condition=condition)
        routing = _routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.2")])
        _firewall(graph, B, "rb:b", [])
        net = _network(routing)
        assert ev.answer(net, request).lower == CLIENTS

        one_backend = ev.evaluate(net, _changes(_deny_intent("rb:b", "203.0.113.31")), request)
        assert one_backend.proven_loss == ()
        assert one_backend.possible_loss == ()
        assert one_backend.members["be1"].proven_loss == one_backend.before.members["be1"].request

        two_backends = ev.evaluate(
            net, _changes(_deny_intent("rb:b", "203.0.113.31"), _deny_intent("rb:b", "203.0.113.32")), request
        )
        assert two_backends.proven_loss == CLIENTS

        dns = ev.evaluate(net, _changes(_deny_intent("rb:b", "203.0.113.53")), request)
        assert dns.proven_loss == CLIENTS
        assert dns.members["auth"].proven_loss.is_empty()

        # one backend denied and another undetermined: two of three is neither
        # proven nor ruled out
        graph.rules_by_rb["rb:b"] = [_deny("203.0.113.33", action="inspect")]
        undetermined = ev.evaluate(net, _changes(_deny_intent("rb:b", "203.0.113.31")), request)
        assert undetermined.proven_loss == ()
        assert undetermined.possible_loss == CLIENTS
        assert undetermined.after.lower == ()
        assert undetermined.after.upper == CLIENTS

    def test_the_condition_is_evaluated_per_client(self, graph):
        # two client prefixes enter R1 on two interfaces, and B denies one of them
        _firewall(
            graph,
            B,
            "rb:b",
            [_rule(uid="cp:guest", pos=1, action="drop", src_any=False, src_cidrs=["10.0.4.0/24"])],
        )
        interfaces = (
            *_interfaces(),
            ev.Interface(R1, "if:r1-eth3", "eth3", VRF_R1, ("10.0.4.0/24",), ("10.0.4.1",)),
        )
        routing = _routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.2")])
        request = _request(sources=_ivals("10.0.0.0/24", "10.0.4.0/24"))
        answer = ev.answer(_network(routing, interfaces), request)
        assert answer.lower == _ivals("10.0.0.0/24")
        assert answer.upper == _ivals("10.0.0.0/24")
        outcomes = {e.request.src: e.outcome for e in answer.members["app"].explanations}
        assert outcomes == {_ivals("10.0.0.0/24"): ev.HOLDS, _ivals("10.0.4.0/24"): ev.FAILS}


# --- the change -----------------------------------------------------------------------------


class TestApply:
    def test_apply_hands_routing_intents_to_the_engine_and_the_rest_to_the_overlay(self, graph):
        _firewall(graph, A, "rb:a", [])
        net = _network()
        delta = _changes(SHUT_A, _deny_intent("rb:a", APP))
        after = ev.apply(net, delta)
        assert after.changes is delta
        assert net.changes is None
        assert [s.get("state") for s in after.routing.bgp.sessions] == ["shutdown", None]
        assert [s.get("state") for s in net.routing.bgp.sessions] == [None, None]
        # the deny on A's rulebase decides nothing once A is shut, and the
        # baseline still reads the collected rules
        impact = ev.compare(ev.answer(net, _request()), ev.answer(after, _request()))
        assert impact.proven_loss == ()
        assert _only(impact.before).outcome == ev.HOLDS
        # the same deny on B's rulebase is read through the overlay
        _firewall(graph, B, "rb:b", [])
        blocked = ev.evaluate(net, _changes(SHUT_A, _deny_intent("rb:b", APP)), _request())
        assert blocked.proven_loss == CLIENTS
        assert _step(_only(blocked.after), "filter", "deny").device_uid == B
        assert _only(ev.answer(net, _request())).outcome == ev.HOLDS


# --- an interface ACL sits where its binding direction puts it -----------------------------


class TestInterfaceAclOrder:
    """IOS-XE runs an inbound access list before every translation and an
    outbound list after every translation. The walk judges the inbound list at
    the filter step on the original packet and the outbound list at the
    egress-filter step, after source NAT, on the packet as it leaves."""

    @staticmethod
    def _acl(graph, uid, rules, bindings):
        graph.rb_by_dev[R1] = {
            **_rb(uid, "deny"),
            "vendor": "cisco",
            "match_context": "interface-acl",
            "acl_bindings": bindings,
        }
        graph.rules_by_rb[uid] = rules
        graph.iface_names = {"if:r1-eth0": "eth0", "if:r1-eth2": "eth2"}

    def test_an_inbound_acl_is_judged_on_the_original_destination(self, graph):
        public = "198.51.100.10"
        graph.nat_by_dev[R1] = [
            _dnat_row(orig_dst_raw=public, orig_dst_addrs=[public], translation=APP, xlate_dst_addrs=[APP])
        ]
        self._acl(
            graph,
            "acl:wan-in",
            [
                _rule(
                    uid="acl:wan-in:10",
                    pos=10,
                    action="permit",
                    src_any=True,
                    dst_any=False,
                    dst_ips=[public],
                    svc_any=True,
                )
            ],
            [["eth0", "in"]],
        )
        routing = _routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.2")])
        before = ev.answer(_network(routing), _request(dst=public))
        assert before.lower == CLIENTS
        explanation = _only(before)
        assert explanation.outcome == ev.HOLDS
        assert _step(explanation, "dnat", "rewrite").device_uid == R1
        assert _step(explanation, "filter", "original-header").device_uid == R1
        assert _step(explanation, "filter", "permit").device_uid == R1

    def test_an_outbound_acl_is_judged_after_source_nat(self, graph):
        graph.nat_by_dev[R1] = [
            _nat_row(
                kind="snat",
                orig_src_addrs=["10.0.0.0/24"],
                translation="10.0.2.1",
                xlate_src_addrs=["10.0.2.1"],
                out_if="eth2",
            )
        ]
        self._acl(
            graph,
            "acl:wan-out",
            [
                _rule(
                    uid="acl:wan-out:10",
                    pos=10,
                    action="permit",
                    src_any=False,
                    src_ips=["10.0.2.1"],
                    dst_any=True,
                    svc_any=True,
                )
            ],
            [["eth2", "out"]],
        )
        routing = _routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.2")])
        before = ev.answer(_network(routing), _request())
        assert before.lower == CLIENTS
        explanation = _only(before)
        assert explanation.outcome == ev.HOLDS
        assert _step(explanation, "snat", "rewrite").device_uid == R1
        assert _step(explanation, "egress-filter", "permit").device_uid == R1
        # the list was not a candidate at the filter step, which passed the flow
        assert [s.kind for s in explanation.steps if s.stage == "filter" and s.device_uid == R1] == ["pass"]

    def test_an_outbound_acl_deny_after_source_nat_is_a_proven_failure(self, graph):
        graph.nat_by_dev[R1] = [
            _nat_row(
                kind="snat",
                orig_src_addrs=["10.0.0.0/24"],
                translation="10.0.2.1",
                xlate_src_addrs=["10.0.2.1"],
                out_if="eth2",
            )
        ]
        self._acl(
            graph,
            "acl:wan-out",
            [
                _rule(
                    uid="acl:wan-out:10",
                    pos=10,
                    action="permit",
                    src_any=False,
                    src_ips=["198.51.100.7"],
                    dst_any=True,
                    svc_any=True,
                )
            ],
            [["eth2", "out"]],
        )
        routing = _routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.2")])
        before = ev.answer(_network(routing), _request())
        assert before.lower == ()
        assert before.upper == ()
        explanation = _only(before)
        assert explanation.outcome == ev.FAILS
        assert _step(explanation, "egress-filter", "deny").device_uid == R1


class TestOwnAddresses:
    def test_a_device_holding_both_families_orders_by_family_then_value(self):
        # A VyOS twin carries the operational IPv6 GUA beside the configured
        # IPv4 addresses (collectors/vyos.py). Address objects of different
        # families raise TypeError on comparison, so the order is by family.
        interfaces = (
            ev.Interface(R1, "if:r1-eth0", "eth0", VRF_R1, ("10.0.0.0/24",), ("10.0.0.1",)),
            ev.Interface(
                R1, "if:r1-eth1", "eth1", VRF_R1, ("2001:db8:1::/64",), ("2001:db8:1::1", "10.0.1.1")
            ),
            ev.Interface(A, "if:a-eth0", "eth0", VRF_A, ("10.0.1.0/30",), ("10.0.1.2",)),
        )
        net = _network(interfaces=interfaces)
        assert net.own_addresses(R1, VRF_R1) == ("10.0.0.1", "10.0.1.1", "2001:db8:1::1")
        assert net.own_addresses(A, VRF_A) == ("10.0.1.2",)
