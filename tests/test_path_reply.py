# ruff: noqa: F811

import importlib

import pytest
from tests.test_path_nat import _nat_row
from tests.test_path_trace import (  # noqa: F401
    GW,
    GW_GUEST,
    GW_LAN,
    FakeGraph,
    _pbr_row,
    _route,
    _src_row,
    _zone_rb_row,
    _zoned_router,
    graph,
)

from hst import path
from hst.path import DENY, INDETERMINATE, PERMIT
from hst.path.addrsets import _describe, _intervals
from hst.path.gates.firewall import _apply_firewall_reply

tracemod = importlib.import_module("hst.path.trace")
_build_reply_tuple = tracemod._build_reply_tuple


def _step(device, direction, pre_src, pre_dst, post_src, post_dst, rule_uid="r1", **extra):
    return {
        "device": device,
        "direction": direction,
        "rule_uid": rule_uid,
        "pre": {"src": pre_src, "dst": pre_dst},
        "post": {"src": post_src, "dst": post_dst},
        **extra,
    }


SRC = _intervals(["10.0.0.5/32"])
DST = _intervals(["203.0.113.10/32"])


def test_no_nat_reply_tuple_is_the_plain_swap():
    leg = {}
    reply_src, reply_dst, lb_note = _build_reply_tuple(leg, SRC, DST)
    assert reply_src == DST
    assert reply_dst == SRC
    assert lb_note is None


def test_single_dnat_reply_carries_the_original_virtual_destination_as_its_source():
    leg = {
        "nat_chain": [
            _step(
                "dev:r1",
                "dnat",
                pre_src=["10.0.0.5/32"],
                pre_dst=["203.0.113.10/32"],
                post_src=["10.0.0.5/32"],
                post_dst=["10.0.0.99/32"],
            )
        ]
    }
    reply_src, reply_dst, lb_note = _build_reply_tuple(leg, SRC, DST)
    assert reply_src == _intervals(["203.0.113.10/32"])
    assert reply_dst == SRC
    assert lb_note is None


def test_single_snat_reply_carries_the_original_private_source_as_its_destination():
    """The masquerade address the forward flow left egress with is never the
    reply's own destination; the client's real, pre-translation address is."""
    leg = {
        "nat_chain": [
            _step(
                "dev:r1",
                "snat",
                pre_src=["10.0.0.5/32"],
                pre_dst=["8.8.8.8/32"],
                post_src=["203.0.113.7/32"],
                post_dst=["8.8.8.8/32"],
            )
        ]
    }
    dst = _intervals(["8.8.8.8/32"])
    reply_src, reply_dst, lb_note = _build_reply_tuple(leg, SRC, dst)
    assert reply_src == dst
    assert reply_dst == SRC
    assert lb_note is None


def test_dnat_then_snat_reply_undoes_both_in_reverse_device_order():
    """r1's dNAT and r2's sNAT (the multi-hop case test_path_nat.py records
    the chain for) each undo independently: the reply's source is the
    virtual address r1 dNAT'd away, its destination is the private address
    r2's masquerade hid, and the transit address between them never
    appears on either end."""
    leg = {
        "nat_chain": [
            _step(
                "dev:r1",
                "dnat",
                pre_src=["10.0.0.5/32"],
                pre_dst=["203.0.113.10/32"],
                post_src=["10.0.0.5/32"],
                post_dst=["10.0.0.99/32"],
            ),
            _step(
                "dev:r2",
                "snat",
                pre_src=["10.0.0.5/32"],
                pre_dst=["10.0.0.99/32"],
                post_src=["10.0.12.1/32"],
                post_dst=["10.0.0.99/32"],
            ),
        ]
    }
    reply_src, reply_dst, lb_note = _build_reply_tuple(leg, SRC, DST)
    assert reply_src == _intervals(["203.0.113.10/32"])
    assert reply_dst == SRC
    assert lb_note is None


def test_double_dnat_hairpin_reply_restores_the_first_virtual_address():
    """Two dNAT rewrites of the destination, hairpinned through two devices:
    the reply's source is the FIRST virtual address the client used, not
    the intermediate one the second dNAT rewrote from."""
    leg = {
        "nat_chain": [
            _step(
                "dev:r1",
                "dnat",
                pre_src=["10.0.0.5/32"],
                pre_dst=["203.0.113.10/32"],
                post_src=["10.0.0.5/32"],
                post_dst=["10.0.0.50/32"],
            ),
            _step(
                "dev:r2",
                "dnat",
                pre_src=["10.0.0.5/32"],
                pre_dst=["10.0.0.50/32"],
                post_src=["10.0.0.5/32"],
                post_dst=["10.0.0.99/32"],
            ),
        ]
    }
    reply_src, reply_dst, lb_note = _build_reply_tuple(leg, SRC, DST)
    assert reply_src == _intervals(["203.0.113.10/32"])
    assert reply_dst == SRC
    assert lb_note is None


def test_a_load_balancer_step_is_undone_but_named_indeterminate():
    leg = {
        "nat_chain": [
            _step(
                "dev:lb1",
                "lb",
                pre_src=["10.0.0.5/32"],
                pre_dst=["203.0.113.20/32"],
                post_src=["10.0.0.5/32"],
                post_dst=["10.0.5.7/32"],
                vip_name="web-vip",
            )
        ]
    }
    dst = _intervals(["203.0.113.20/32"])
    reply_src, reply_dst, lb_note = _build_reply_tuple(leg, SRC, dst)
    assert reply_src == dst
    assert reply_dst == SRC
    assert lb_note == "web-vip"


def _rb(**kw):
    base = {
        "rb_uid": "cp:rb1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": "deny",
        "approximate": False,
    }
    return {**base, **kw}


def _rule(**kw):
    base = {
        "uid": "cp:r1",
        "pos": 1,
        "action": "accept",
        "name": None,
        "out_if": None,
        "in_if": None,
        "src_any": False,
        "dst_any": False,
        "svc_any": False,
        "src_cidrs": [],
        "src_ips": [],
        "dst_cidrs": [],
        "dst_ips": [],
        "protos": [],
        "ports": [],
        "src_ranges": [],
        "dst_ranges": [],
    }
    return {**base, **kw}


def test_a_device_with_no_collected_state_policy_evaluates_the_reply_on_its_own_rules(monkeypatch):
    rb = _rb()
    rules = [_rule(src_any=True, dst_any=True, svc_any=True, action="accept")]

    def fake_read_one(session, query, **params):
        return None  # global_state_policy was never collected

    def fake_read(session, query, **params):
        if "HAS_RULE" in query:
            return rules
        if "ENFORCES" in query:
            return [rb]
        return []

    monkeypatch.setattr(path, "_read_one", fake_read_one)
    monkeypatch.setattr(path, "_read", fake_read)

    trail = path._Trail()
    leg: dict = {}
    outcome = _apply_firewall_reply(
        None,
        trail,
        leg,
        {"dev_uid": "dev:cp1", "dev_name": "cp1", "if_uid": "if:in"},
        "if:out",
        _intervals(["203.0.113.10"]),
        _intervals(["10.0.0.5"]),
        None,
        None,
        "203.0.113.10",
        "eth0",
    )
    assert outcome == PERMIT
    assert leg.get("indeterminate") is not True
    assert "admitted from session state" not in leg.get("firewall", "")


def test_a_cisco_acl_with_no_rule_covering_the_return_blocks_the_reply(monkeypatch):
    rb = {
        **_rb(),
        "vendor": "cisco",
        "match_context": "interface-acl",
        "rb_uid": "cisco:edge-in",
        "acl_bindings": [["Gi0/1", "in"]],
    }
    # written for the forward direction only: matches 10.0.0.5 -> 203.0.113.10
    rules = [
        _rule(
            action="permit",
            src_ips=["10.0.0.5"],
            dst_ips=["203.0.113.10"],
            svc_any=True,
        )
    ]

    def fake_read_one(session, query, **params):
        return None

    def fake_read(session, query, **params):
        if "HAS_RULE" in query:
            return rules
        if "ENFORCES" in query:
            return [rb]
        if "i.uid IN" in query:
            return [{"uid": "if:in", "name": "Gi0/1"}]
        return []

    monkeypatch.setattr(path, "_read_one", fake_read_one)
    monkeypatch.setattr(path, "_read", fake_read)

    trail = path._Trail()
    leg: dict = {}
    # the reply's own tuple: 203.0.113.10 -> 10.0.0.5, on the same interface
    outcome = _apply_firewall_reply(
        None,
        trail,
        leg,
        {"dev_uid": "dev:edge1", "dev_name": "edge1", "if_uid": "if:in"},
        "if:out",
        _intervals(["203.0.113.10"]),
        _intervals(["10.0.0.5"]),
        None,
        None,
        "203.0.113.10",
        "eth0",
    )
    assert outcome == DENY
    assert leg.get("blocked") is True


def test_a_device_the_forward_walk_never_crossed_evaluates_the_reply_as_a_new_connection(monkeypatch):
    rb = _rb(rb_uid="vyos:rb1", vendor="vyos", default_action="deny")
    rules = [_rule(action="permit", src_any=True, dst_any=True, svc_any=True, states=["established"])]

    def fake_read_one(session, query, **params):
        if "global_state_policy" in query:
            return {"global_state_policy": ["established", "related"]}
        return None

    def fake_read(session, query, **params):
        if "HAS_RULE" in query:
            return rules
        if "ENFORCES" in query:
            return [rb]
        return []

    monkeypatch.setattr(path, "_read_one", fake_read_one)
    monkeypatch.setattr(path, "_read", fake_read)

    trail = path._Trail()
    # the forward walk never visited this device: no entry in device_gate_state
    leg: dict = {}
    outcome = _apply_firewall_reply(
        None,
        trail,
        leg,
        {"dev_uid": "dev:f3", "dev_name": "f3", "if_uid": "if:in"},
        "if:out",
        _intervals(["203.0.113.10"]),
        _intervals(["10.0.0.5"]),
        None,
        None,
        "203.0.113.10",
        "eth0",
    )
    assert outcome == DENY
    assert leg.get("blocked") is True


def test_a_no_route_leg_in_reply_mode_reads_session_state(monkeypatch):
    from hst.path.gates.routing import _no_route_leg

    rb = _rb(rb_uid="vyos:rb1", vendor="vyos", default_action="deny")
    rules = [_rule(action="permit", src_any=True, dst_any=True, svc_any=True, states=["established"])]

    def fake_read_one(session, query, **params):
        return None  # global_state_policy was never collected

    def fake_read(session, query, **params):
        if "HAS_RULE" in query:
            return rules
        if "ENFORCES" in query:
            return [rb]
        return []

    monkeypatch.setattr(path, "_read_one", fake_read_one)
    monkeypatch.setattr(path, "_read", fake_read)

    gw = {"dev_uid": "dev:f3", "dev_name": "f3", "if_uid": "if:in"}
    grp = {"sources": SRC, "table_name": "vrf:main"}

    trail = path._Trail()
    trail.device_gate_state["dev:f3"] = {"policy": None, "permit": True}
    leg = _no_route_leg(None, trail, grp, gw, DST, 0, "203.0.113.10", None, None, conn_state="established")
    assert leg["verdict"] == "no route found"
    assert leg.get("blocked") is not True

    fresh_trail = path._Trail()
    fresh_leg = _no_route_leg(None, fresh_trail, grp, gw, DST, 0, "10.0.0.5", None, None)
    assert fresh_leg["blocked"] is True


R2_IF = {"dev_uid": "dev:r2", "dev_name": "r2", "if_uid": "if:r2-eth0", "if_name": "r2-eth0"}

_walk_reply_leg = tracemod._walk_reply_leg
ORIG_SRC = _intervals(["10.0.0.5"])
ORIG_DST = _intervals(["10.99.0.7"])


def test_a_symmetric_round_trip_produces_no_asymmetric_note(graph):
    """One device, one route home: the reply's own walk lands back on the
    same device the forward flow's terminal names, and the sequences match
    once reversed."""
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth1", kind="ORIGINATES")]}
    terminal = {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:eth2", "if_name": "eth2"}
    result = _walk_reply_leg(None, {}, terminal, ["dev:r1"], {}, ORIG_SRC, ORIG_DST, None, max_hops=8)
    assert result["asymmetric"] is False
    assert result["comparison_notes"] == []
    assert result["legs"][0]["verdict"] == "egress via eth1"
    assert not result["indeterminate"]
    assert not result["boundary"]


def test_an_asymmetric_return_link_is_named_with_both_device_sequences(graph):
    graph.default_tables = {"if:r2-eth5": {"uid": "vrf:r2"}}
    graph.routes = {"vrf:r2": [_route("10.0.0.0/24", egress="r2-eth9", kind="ORIGINATES")]}
    terminal = {"dev_uid": "dev:r2", "dev_name": "r2", "if_uid": "if:r2-eth5", "if_name": "r2-eth5"}
    result = _walk_reply_leg(
        None, {}, terminal, ["dev:r1", "dev:r2"], {}, ORIG_SRC, ORIG_DST, None, max_hops=8
    )
    assert result["asymmetric"] is True
    notes = " ".join(result["comparison_notes"])
    assert "asymmetric routing" in notes
    assert "dev:r1" in notes and "dev:r2" in notes
    assert result["legs"][0]["verdict"] == "egress via r2-eth9"


def _ecmp_reply_diamond(graph, *, back_via_b_only: bool = False):
    """The forward lane crossed r1, r2a and r3; r3 returns 10.0.0.0/24 over
    two equal-cost next hops, r2a and r2b, which both hand it to r1."""
    r3 = {"dev_uid": "dev:r3", "dev_name": "r3", "if_uid": "if:r3-in", "if_name": "r3-in"}
    r2a = {"dev_uid": "dev:r2a", "dev_name": "r2a", "if_uid": "if:r2a-in", "if_name": "r2a-in"}
    r2b = {"dev_uid": "dev:r2b", "dev_name": "r2b", "if_uid": "if:r2b-in", "if_name": "r2b-in"}
    r1a = {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:r1-a", "if_name": "r1-a"}
    r1b = {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:r1-b", "if_name": "r1-b"}
    graph.default_tables = {
        r3["if_uid"]: {"uid": "vrf:r3"},
        r2a["if_uid"]: {"uid": "vrf:r2a"},
        r2b["if_uid"]: {"uid": "vrf:r2b"},
        r1a["if_uid"]: {"uid": "vrf:r1"},
        r1b["if_uid"]: {"uid": "vrf:r1"},
    }
    back = [_route("10.0.0.0/24", egress="r3-b", next_hop="10.0.32.3")]
    if not back_via_b_only:
        back.insert(0, _route("10.0.0.0/24", egress="r3-a", next_hop="10.0.32.2"))
    graph.routes = {
        "vrf:r3": back,
        "vrf:r2a": [_route("10.0.0.0/24", egress="r2a-out", next_hop="10.0.21.1")],
        "vrf:r2b": [_route("10.0.0.0/24", egress="r2b-out", next_hop="10.0.31.1")],
        "vrf:r1": [_route("10.0.0.0/24", egress="eth1", kind="ORIGINATES")],
    }
    graph.next_hop_devs = {"10.0.32.2": r2a, "10.0.32.3": r2b, "10.0.21.1": r1a, "10.0.31.1": r1b}
    return r3


def test_a_symmetric_ecmp_reply_is_compared_lane_by_lane(graph):
    terminal = _ecmp_reply_diamond(graph)
    forward = ["dev:r1", "dev:r2a", "dev:r3"]
    result = _walk_reply_leg(None, {}, terminal, forward, {}, ORIG_SRC, ORIG_DST, None, max_hops=8)

    assert len({ll["lane"] for ll in result["legs"]}) == 2
    assert result["asymmetric"] is False
    assert result["comparison_notes"] == [
        "reply lane 1 (dev:r3 → dev:r2b → dev:r1) does not match the forward path reversed "
        "(dev:r3 → dev:r2a → dev:r1), which reply lane 0 retraces"
    ]


def test_an_ecmp_reply_over_parallel_links_is_symmetric_with_no_note(graph):
    terminal = _ecmp_reply_diamond(graph)
    # both equal-cost next hops are r2a's, over two links
    graph.next_hop_devs["10.0.32.3"] = {
        "dev_uid": "dev:r2a",
        "dev_name": "r2a",
        "if_uid": "if:r2a-in2",
        "if_name": "r2a-in2",
    }
    graph.default_tables["if:r2a-in2"] = {"uid": "vrf:r2a"}
    forward = ["dev:r1", "dev:r2a", "dev:r3"]
    result = _walk_reply_leg(None, {}, terminal, forward, {}, ORIG_SRC, ORIG_DST, None, max_hops=8)

    assert len({ll["lane"] for ll in result["legs"]}) == 2
    assert result["asymmetric"] is False
    assert result["comparison_notes"] == []


def test_an_asymmetric_ecmp_reply_names_each_lane(graph):
    terminal = _ecmp_reply_diamond(graph, back_via_b_only=True)
    forward = ["dev:r1", "dev:r2a", "dev:r3"]
    gates = {"dev:r2a": {"verdict": PERMIT}}
    result = _walk_reply_leg(None, {}, terminal, forward, gates, ORIG_SRC, ORIG_DST, None, max_hops=8)

    assert result["asymmetric"] is True
    assert result["comparison_notes"] == [
        "asymmetric routing: the reply's own path (dev:r3 → dev:r2b → dev:r1) does not match "
        "the forward path reversed (dev:r3 → dev:r2a → dev:r1)",
        "reply does not cross dev:r2a; its session state does not apply",
    ]


def test_the_reply_comparison_names_every_lane_when_none_retraces_the_forward_lane():
    asymmetric, notes = tracemod._reply_comparison(
        ["dev:r1", "dev:r2", "dev:r3"],
        {0: ["dev:r3", "dev:r4", "dev:r1"], 1: ["dev:r3", "dev:r5", "dev:r1"]},
        {"dev:r2": {"verdict": PERMIT}},
    )

    assert asymmetric is True
    assert notes == [
        "asymmetric routing: no lane of the reply's own path (lane 0: dev:r3 → dev:r4 → dev:r1; "
        "lane 1: dev:r3 → dev:r5 → dev:r1) matches the forward path reversed (dev:r3 → dev:r2 → dev:r1)",
        "reply lane 0 does not cross dev:r2; its session state does not apply",
        "reply lane 1 does not cross dev:r2; its session state does not apply",
    ]


def test_a_reply_with_no_terminal_is_indeterminate_not_derived(graph):
    result = _walk_reply_leg(None, {}, None, [], {}, ORIG_SRC, ORIG_DST, None, max_hops=8)
    assert result["indeterminate"] is True
    assert result["legs"] == []


def test_a_reply_with_no_next_hop_in_the_graph_sets_boundary(graph):
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth1", next_hop="10.0.0.254")]}
    terminal = {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:eth2", "if_name": "eth2"}
    result = _walk_reply_leg(None, {}, terminal, ["dev:r1"], {}, ORIG_SRC, ORIG_DST, None, max_hops=8)
    reply_leg = result["legs"][0]
    assert reply_leg["boundary"] is True
    assert not reply_leg["blocked"]
    assert "BLOCKED" not in reply_leg["verdict"]
    assert result["boundary"] is True


def test_a_reply_over_two_source_groups_names_each_group_in_its_verdict(graph, monkeypatch):
    """The reply walk drops each leg's `gid` before it returns, so the group
    count is taken first: two groups give the multi-group verdict, which
    names each leg's own source and is never read as ECMP over one route."""

    def _leg(gid, src):
        return {
            "gid": gid,
            "src_label": src,
            "egress": "eth1",
            "next_hop": None,
            "cidr": "10.0.0.0/24",
            "table": "main",
            "blocked": False,
        }

    def stage(*_args, **_kwargs):
        return [_leg(0, "10.99.0.7"), _leg(1, "10.99.0.8")], 2

    monkeypatch.setattr(tracemod, "_device_stage", stage)
    terminal = {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:eth2", "if_name": "eth2"}
    result = _walk_reply_leg(None, {}, terminal, ["dev:r1"], {}, ORIG_SRC, ORIG_DST, None, max_hops=8)
    assert all("gid" not in ll for ll in result["legs"])
    assert result["verdict"] == tracemod._combined_verdict(result["legs"], "reply", True)
    assert result["verdict"] != tracemod._combined_verdict(result["legs"], "reply", False)
    assert "10.99.0.8" in result["verdict"]


def test_reply_omitted_is_byte_for_byte_the_default_shape(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.99.0.0/24", egress="eth2")]}
    plain = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    explicit = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW], reply=False)
    assert plain == explicit
    assert set(plain) == {
        "hops",
        "legs",
        "verdict",
        "notes",
        "warnings",
        "indeterminate",
        "boundary",
        # where the walk left the estate, and where its paths end
        "left_estate",
        "reach",
    }


def test_reply_true_nests_both_directions(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.99.0.0/24", egress="eth2"),
            _route("10.0.0.0/24", egress="eth1"),
        ]
    }
    forward_only = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW], reply=True)
    assert result["forward"] == forward_only
    assert result["reply"]["legs"]
    assert isinstance(result["asymmetric"], bool)
    assert isinstance(result["notes"], list)


def test_reply_true_on_a_network_scoped_trace_is_answered_not_refused(graph):
    graph.routes = {
        "vrf:main": [
            _route("10.99.0.0/24", egress="eth2"),
            _route("10.0.0.0/24", egress="eth1"),
        ]
    }
    result = path.trace(None, "10.0.0.0/24", "10.99.0.7", gateways=[GW], reply=True)
    assert set(result) == {"forward", "reply", "asymmetric", "notes"}
    assert result["reply"]["legs"]


def test_reply_true_on_a_multi_interpretation_source_raises(graph):
    graph.sources = [
        _src_row("home") | {"anchor": "vrf:dev:r1:home"},
        _src_row("home") | {"anchor": "vrf:dev:r2:home"},
    ]
    graph.routes = {"vrf:main": [_route("10.99.0.0/24", egress="eth2")]}
    with pytest.raises(ValueError, match="source interpretations"):
        path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW], reply=True)


def test_reply_true_on_a_multi_interpretation_slash_32_source_raises(graph):
    graph.sources = [
        _src_row("home") | {"anchor": "vrf:dev:r1:home"},
        _src_row("home") | {"anchor": "vrf:dev:r2:home"},
    ]
    graph.routes = {"vrf:main": [_route("10.99.0.0/24", egress="eth2")]}
    with pytest.raises(ValueError, match="source interpretations"):
        path.trace(None, "10.0.0.5/32", "10.99.0.7", gateways=[GW], reply=True)


def test_reply_true_on_a_zpa_brokered_trace_raises():
    with pytest.raises(ValueError, match="ZPA"):
        tracemod.trace_from_identity(None, "id:g1", "seg:s1", None, None, gateways=[GW], reply=True)


def test_the_state_policy_read_covers_zone_bound_rulebases():
    from hst.path.gates.firewall import _DEVICE_STATE_POLICY_QUERY as q

    assert "ENFORCES" in q
    assert "FROM_ZONE" in q and "TO_ZONE" in q and "CONTAINS" in q
    assert "global_state_policy IS NOT NULL" in q


def _reply_under_policy(monkeypatch, policy, rules, default_action="deny"):
    """One reply leg through a VyOS device whose forward leg was a confirmed
    permit, with `policy` as the device's recorded global state policy."""
    rb = _rb(rb_uid="vyos:fwd", rb_name="ipv4-forward", vendor="vyos", default_action=default_action)

    def fake_read_one(session, query, **params):
        if "global_state_policy" in query:
            return {"global_state_policy": policy, "state_policy_basis": None}
        return None

    def fake_read(session, query, **params):
        if "HAS_RULE" in query:
            return rules
        if "ENFORCES" in query:
            return [rb]
        return []

    monkeypatch.setattr(path, "_read_one", fake_read_one)
    monkeypatch.setattr(path, "_read", fake_read)
    trail = path._Trail()
    trail.device_gate_state["dev:gw"] = {"policy": policy, "permit": True}
    leg: dict = {}
    outcome = _apply_firewall_reply(
        None,
        trail,
        leg,
        {"dev_uid": "dev:gw", "dev_name": "gw", "if_uid": "if:in"},
        "if:out",
        _intervals(["203.0.113.10"]),
        _intervals(["10.0.0.5"]),
        None,
        None,
        "203.0.113.10",
        "eth0",
    )
    return outcome, leg, trail


def test_a_state_policy_with_no_established_action_leaves_the_reply_to_the_rules(monkeypatch):
    rules = [_rule(action="drop", src_any=True, dst_any=True, svc_any=True)]
    outcome, leg, _trail = _reply_under_policy(monkeypatch, ["invalid=drop"], rules)
    assert outcome == DENY
    assert leg.get("blocked") is True
    assert "admitted from session state" not in leg.get("firewall", "")


def test_a_state_policy_that_drops_established_traffic_blocks_the_reply(monkeypatch):
    """`established=drop` drops the reply ahead of every ruleset, so a
    rule that accepts established traffic must not be shown permitting it."""
    rules = [_rule(action="accept", src_any=True, dst_any=True, svc_any=True, states=["established"])]
    outcome, leg, trail = _reply_under_policy(monkeypatch, ["established=drop", "invalid=drop"], rules)
    assert outcome == DENY
    assert leg["blocked"] is True
    assert "global state policy" in leg["verdict"]
    assert leg["fw_uid"] == "vyos:fwd"
    assert any("drops established traffic" in n for n in trail.notes)


def test_a_state_policy_with_conflicting_established_actions_leaves_the_reply_undecided(monkeypatch):
    """Two different established actions cannot both hold, so the
    reply is neither admitted nor blocked."""
    rules = [_rule(action="accept", src_any=True, dst_any=True, svc_any=True)]
    outcome, leg, trail = _reply_under_policy(monkeypatch, ["established=accept", "established=drop"], rules)
    assert outcome == INDETERMINATE
    assert leg["indeterminate"] is True
    assert leg.get("blocked") is not True
    assert any("NOT confirmed permitted" in w for w in trail.warnings)


def test_the_established_action_is_read_per_state():
    from hst.path.gates.firewall import _established_action

    assert _established_action(["established=accept", "related=accept"]) == PERMIT
    assert _established_action(["established=reject"]) == DENY
    assert _established_action(["invalid=drop", "related=accept"]) is None
    assert _established_action(["established"]) is None
    assert _established_action(["established=log"]) == INDETERMINATE


def test_a_reply_through_the_route_leg_is_admitted_from_session_state(graph, monkeypatch):
    from hst.path.gates import firewall as fwmod

    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.99.0.0/24", egress="eth2"),
            _route("10.0.0.0/24", egress="eth1"),
        ]
    }
    # the forward chain permits by default action; nothing else governs
    graph.rb = _rb(rb_uid="vyos:fwd", vendor="vyos", default_action="accept")
    graph.rules = []
    monkeypatch.setattr(
        fwmod, "_device_state_policy", lambda session, dev: ["established=accept", "related=accept"]
    )

    result = path.trace(None, "10.0.0.5", "10.99.0.7", port=443, proto="tcp", gateways=[GW], reply=True)

    assert result["forward"]["legs"][0]["blocked"] is False
    reply_leg = result["reply"]["legs"][0]
    assert reply_leg["blocked"] is False
    assert str(reply_leg.get("firewall", "")).startswith("admitted from session state")
    fw_hop = next(h for h in result["reply"]["hops"] if h["kind"] == "FwRulebase")
    assert fw_hop["uid"] == "vyos:fwd"
    assert str(fw_hop["note"]).startswith("admitted from session state")


def test_a_reply_with_no_nat_and_no_rulebase_records_origin_and_ingress_only(graph):
    terminal = {
        "dev_uid": "dev:r1",
        "dev_name": "r1",
        "if_uid": "if:eth2",
        "if_name": "eth2",
        "origin": {"uid": "wan:isp", "kind": "WanLink", "label": "1und1"},
    }
    result = _walk_reply_leg(
        None, {"boundary": True}, terminal, ["dev:r1"], {}, ORIG_SRC, ORIG_DST, None, max_hops=8
    )
    first_two = [(h["kind"], h["stage"], h["note"]) for h in result["hops"][:2]]
    assert first_two == [
        ("WanLink", "SRC_ENDPOINT", f"reply origin: {_describe(ORIG_DST)}, outside the twin"),
        ("Interface", "INGRESS_IF", "reply ingress"),
    ]
    assert not any(h["kind"] == "NatRule" for h in result["hops"])
    ranks = [h["rank"] for h in result["hops"]]
    assert ranks == sorted(ranks)


def test_a_reply_undoes_a_snat_at_the_first_device_by_its_recorded_label(graph):
    """The undo station names the forward rule by the label the forward
    walk itself recorded for it (`nat_rule_labels`), never by re-matching
    the rule, and states the addresses the forward walk's own tuples name:
    the masquerade address back to the private one."""
    terminal = {
        "dev_uid": "dev:r1",
        "dev_name": "r1",
        "if_uid": "if:pppoe0",
        "if_name": "pppoe0",
        "origin": {"uid": "wan:isp", "kind": "WanLink", "label": "1und1"},
    }
    forward_leg = {
        "boundary": True,
        "nat_chain": [
            _step(
                "dev:r1",
                "snat",
                pre_src=["192.168.10.89/32"],
                pre_dst=["8.8.8.8/32"],
                post_src=["198.51.100.182/32"],
                post_dst=["8.8.8.8/32"],
                rule_uid="nat:r10",
            )
        ],
    }
    orig_src = _intervals(["192.168.10.89/32"])
    orig_dst = _intervals(["8.8.8.8/32"])
    result = _walk_reply_leg(
        None,
        forward_leg,
        terminal,
        ["dev:r1"],
        {},
        orig_src,
        orig_dst,
        None,
        max_hops=8,
        nat_rule_labels={"nat:r10": "sNAT rule 10"},
    )
    nat_hop = next(h for h in result["hops"] if h["kind"] == "NatRule")
    assert nat_hop["stage"] == "DNAT"
    assert nat_hop["label"] == "sNAT rule 10"
    assert nat_hop["note"] == "undoes sNAT rule 10: 198.51.100.182 -> 192.168.10.89"
    kinds_and_stages = [(h["kind"], h["stage"]) for h in result["hops"][:3]]
    assert kinds_and_stages == [
        ("WanLink", "SRC_ENDPOINT"),
        ("Interface", "INGRESS_IF"),
        ("NatRule", "DNAT"),
    ]
    ranks = [h["rank"] for h in result["hops"]]
    assert ranks == sorted(ranks)


def _zpair(src_zone, dst_zone, rb_uid, rb_name):
    return {
        "rb_uid": rb_uid,
        "rb_name": rb_name,
        "af": 4,
        "default_action": "accept",
        "default_action_unknown": False,
        "global_state_policy": None,
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "zone_default": "accept",
        "zone_default_unknown": False,
    }


def test_a_denied_legs_gate_state_survives_a_sibling_legs_later_permit(monkeypatch):
    from hst.path.gates import firewall as fwmod
    from hst.path.gates.firewall import _apply_firewall

    graph = FakeGraph()
    graph.ingress_zones = {"if:lan": "LAN", "if:dmz": "DMZ", "if:wan": "WAN"}
    graph.zone_pairs[("if:lan", "if:wan")] = _zpair("LAN", "WAN", "fw:lan-wan", "LAN-WAN")
    graph.zone_pairs[("if:dmz", "if:wan")] = {
        **_zpair("DMZ", "WAN", "fw:dmz-wan", "DMZ-WAN"),
        "default_action": "drop",
    }
    monkeypatch.setattr(path, "_read", lambda session, query, **p: graph.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: graph.read_one(query, **p))
    monkeypatch.setattr(fwmod, "_device_state_policy", lambda session, dev: ["established=accept"])

    trail = path._Trail()
    leg_denied: dict = {}
    leg_permitted: dict = {}
    outcome_denied = _apply_firewall(
        None,
        trail,
        leg_denied,
        {"dev_uid": "dev:core1", "dev_name": "core1", "if_uid": "if:dmz"},
        "if:wan",
        _intervals(["10.0.20.5"]),
        _intervals(["8.8.8.8"]),
        443,
        "tcp",
        "10.0.20.5",
        "eth0",
    )
    outcome_permitted = _apply_firewall(
        None,
        trail,
        leg_permitted,
        {"dev_uid": "dev:core1", "dev_name": "core1", "if_uid": "if:lan"},
        "if:wan",
        _intervals(["10.0.0.5"]),
        _intervals(["8.8.8.8"]),
        443,
        "tcp",
        "10.0.0.5",
        "eth0",
    )
    assert outcome_denied == DENY
    assert outcome_permitted == PERMIT
    assert leg_denied["gate_state"]["dev:core1"]["permit"] is False
    assert leg_permitted["gate_state"]["dev:core1"]["permit"] is True


def test_the_reply_admission_names_the_reverse_zone_pair_not_the_forward_one(monkeypatch):
    from hst.path.gates import firewall as fwmod

    graph = FakeGraph()
    graph.ingress_zones = {"if:wan": "WAN", "if:lan": "LAN"}
    graph.zone_pairs[("if:lan", "if:wan")] = _zpair("LAN", "WAN", "fw:lan-wan", "LAN-WAN")
    graph.zone_pairs[("if:wan", "if:lan")] = _zpair("WAN", "LAN", "fw:wan-lan", "WAN-LAN")
    monkeypatch.setattr(path, "_read", lambda session, query, **p: graph.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: graph.read_one(query, **p))
    monkeypatch.setattr(
        fwmod, "_device_state_policy", lambda session, dev: ["established=accept", "related=accept"]
    )

    trail = path._Trail()
    trail.device_gate_state["dev:core1"] = {"policy": None, "permit": True}
    leg: dict = {}
    outcome = _apply_firewall_reply(
        None,
        trail,
        leg,
        {"dev_uid": "dev:core1", "dev_name": "core1", "if_uid": "if:wan"},
        "if:lan",
        _intervals(["8.8.8.8"]),
        _intervals(["192.168.10.89"]),
        443,
        "tcp",
        "8.8.8.8",
        "eth0",
    )
    assert outcome == PERMIT
    fw_hop = next(h for h in trail.hops if h["kind"] == "FwRulebase")
    assert fw_hop["uid"] == "fw:wan-lan"
    assert fw_hop["label"] == "WAN-LAN"
    assert str(fw_hop["note"]).startswith("admitted from session state")


def test_a_reply_records_its_first_device_stations_end_to_end(graph, monkeypatch):
    from hst.path.gates import firewall as fwmod

    graph.sources = [_src_row()]
    graph.wan = {"uid": "wan:isp", "name": "1und1"}
    graph.routes = {
        "vrf:main": [
            _route("0.0.0.0/0", egress="eth0"),
            _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES"),
        ]
    }
    graph.iface_addrs = {"if:eth0": "203.0.113.7"}
    graph.nat = [_nat_row(translation="masquerade", out_if="eth0")]
    graph.ingress_zones = {"if:eth0": "WAN", "if:eth1": "LAN"}
    graph.zone_pairs[("if:eth1", "if:eth0")] = _zpair("LAN", "WAN", "fw:lan-wan", "LAN-WAN")
    graph.zone_pairs[("if:eth0", "if:eth1")] = _zpair("WAN", "LAN", "fw:wan-lan", "WAN-LAN")
    monkeypatch.setattr(
        fwmod, "_device_state_policy", lambda session, dev: ["established=accept", "related=accept"]
    )

    forward_only = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW], reply=True)

    assert result["forward"] == forward_only

    reply_hops = result["reply"]["hops"]
    kinds = [(h["kind"], h["stage"]) for h in reply_hops]
    assert kinds[0] == ("WanLink", "SRC_ENDPOINT")
    assert kinds[1] == ("Interface", "INGRESS_IF")
    nat_hop = next(h for h in reply_hops if h["kind"] == "NatRule")
    assert nat_hop["stage"] == "DNAT"
    assert nat_hop["note"] == "undoes sNAT rule 10: 203.0.113.7 -> 10.0.0.5"
    fw_hop = next(h for h in reply_hops if h["kind"] == "FwRulebase")
    assert fw_hop["uid"] == "fw:wan-lan"
    assert fw_hop["label"] == "WAN-LAN"
    assert str(fw_hop["note"]).startswith("admitted from session state")
    ranks = [h["rank"] for h in reply_hops]
    assert ranks == sorted(ranks)
    assert result["reply"]["legs"][0]["blocked"] is False


# --- a network-scoped source, one reply lane per forward leg -----------------------------

R2_REPLY_IF = {"dev_uid": "dev:r2", "dev_name": "r2", "if_uid": "if:r2-eth0", "if_name": "r2-eth0"}


def _split_source(graph):
    """r1's PBR steers 10.0.0.0/25 to table300 and leaves 10.0.0.128/25 on the
    main table, and each table reaches 10.99.0.0/24 by its own egress: the /24
    source fans out into two forward legs, one per half of the source set.

    Each half's reply then starts on its own egress interface and takes its own
    route home: 10.0.0.0/25 comes back over eth1 on r1 alone, matching the
    forward walk reversed, while 10.0.0.128/25 comes back through r2, which the
    forward walk never crossed.
    """
    graph.pbr_by_if = {
        "if:eth1": [
            _pbr_row("pol:split", "SPLIT", "rule:10", "vrf:t300", "table300", src_cidrs=["10.0.0.0/25"])
        ]
    }
    graph.default_tables = {
        "if:eth2": {"uid": "vrf:back-a"},
        "if:eth3": {"uid": "vrf:back-b"},
        "if:r2-eth0": {"uid": "vrf:r2"},
    }
    graph.routes = {
        "vrf:t300": [_route("10.99.0.0/24", egress="eth2")],
        "vrf:main": [_route("10.99.0.0/24", egress="eth3")],
        "vrf:back-a": [_route("10.0.0.0/25", egress="eth1")],
        "vrf:back-b": [_route("10.0.0.128/25", egress="eth0", next_hop="10.0.12.2")],
        "vrf:r2": [_route("10.0.0.128/25", egress="r2-eth5")],
    }
    graph.next_hop_devs = {"10.0.12.2": R2_REPLY_IF}


def test_a_network_scoped_source_answers_one_reply_lane_per_forward_leg(graph):
    _split_source(graph)

    result = path.trace(None, "10.0.0.0/24", "10.99.0.7", gateways=[GW], reply=True)

    assert [ll["src_label"] for ll in result["forward"]["legs"]] == ["10.0.0.0/25", "10.0.0.128/25"]
    lanes = result["reply"]
    assert isinstance(lanes, list)
    assert [lane["forward_leg"] for lane in lanes] == [0, 1]
    assert [lane["src_label"] for lane in lanes] == ["10.0.0.0/25", "10.0.0.128/25"]
    assert [lane["destinations"] for lane in lanes] == [["10.0.0.0/25"], ["10.0.0.128/25"]]
    assert [lane["verdict"] for lane in lanes] == [
        "reply: egress via eth1 (10.0.0.0/25, main table)",
        "reply: egress via r2-eth5 (10.0.0.128/25, main table)",
    ]
    # each lane is its own pane, so its own lanes are numbered from zero
    assert all(h["lane"] == 0 for lane in lanes for h in lane["hops"])


def test_the_asymmetric_comparison_is_made_per_forward_and_reply_pair(graph):
    _split_source(graph)

    result = path.trace(None, "10.0.0.0/24", "10.99.0.7", gateways=[GW], reply=True)

    lanes = result["reply"]
    assert [lane["asymmetric"] for lane in lanes] == [False, True]
    # the top-level flag is the disjunction, and only the asymmetric pair's own
    # comparison note is raised to it
    assert result["asymmetric"] is True
    notes = " ".join(result["notes"])
    assert notes.count("asymmetric routing") == 1
    assert "dev:r2" in notes


R3_IN = {"dev_uid": "dev:r3", "dev_name": "r3", "if_uid": "if:r3-in", "if_name": "r3-in"}
R4_IN = {"dev_uid": "dev:r4", "dev_name": "r4", "if_uid": "if:r4-in", "if_name": "r4-in"}
R1_FROM_R3 = {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:r1-in-a", "if_name": "r1-in-a"}
R1_FROM_R4 = {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:r1-in-b", "if_name": "r1-in-b"}


def _diverging_legs(graph):
    graph.pbr_by_if = {
        "if:eth1": [
            _pbr_row("pol:split", "SPLIT", "rule:10", "vrf:t300", "table300", src_cidrs=["10.0.0.0/25"])
        ]
    }
    graph.default_tables = {
        R3_IN["if_uid"]: {"uid": "vrf:r3"},
        R4_IN["if_uid"]: {"uid": "vrf:r4"},
        "if:r3-out": {"uid": "vrf:r3-reply"},
        "if:r4-out": {"uid": "vrf:r4-reply"},
        R1_FROM_R3["if_uid"]: {"uid": "vrf:r1-reply-a"},
        R1_FROM_R4["if_uid"]: {"uid": "vrf:r1-reply-b"},
    }
    graph.routes = {
        "vrf:t300": [_route("10.99.0.0/24", egress="eth2", next_hop="10.0.23.3")],
        "vrf:main": [_route("10.99.0.0/24", egress="eth3", next_hop="10.0.24.4")],
        "vrf:r3": [_route("10.99.0.0/24", egress="r3-out")],
        "vrf:r4": [_route("10.99.0.0/24", egress="r4-out")],
        "vrf:r3-reply": [_route("10.0.0.0/25", egress="r3-back", next_hop="10.0.31.1")],
        "vrf:r4-reply": [_route("10.0.0.128/25", egress="r4-back", next_hop="10.0.41.1")],
        "vrf:r1-reply-a": [_route("10.0.0.0/25", egress="eth9")],
        "vrf:r1-reply-b": [_route("10.0.0.128/25", egress="eth9")],
    }
    graph.next_hop_devs = {
        "10.0.23.3": R3_IN,
        "10.0.24.4": R4_IN,
        "10.0.31.1": R1_FROM_R3,
        "10.0.41.1": R1_FROM_R4,
    }


def test_diverging_forward_legs_each_compare_against_their_own_devices(graph):
    _diverging_legs(graph)

    result = path.trace(None, "10.0.0.0/24", "10.99.0.7", gateways=[GW], reply=True)

    lanes = result["reply"]
    assert [lane["asymmetric"] for lane in lanes] == [False, False]
    assert result["asymmetric"] is False
    assert result["notes"] == []


def test_one_diverging_lane_is_asymmetric_while_the_other_stays_symmetric(graph):
    _diverging_legs(graph)
    graph.routes["vrf:r4-reply"] = [_route("10.0.0.128/25", egress="r4-back")]

    result = path.trace(None, "10.0.0.0/24", "10.99.0.7", gateways=[GW], reply=True)

    lanes = result["reply"]
    assert [lane["asymmetric"] for lane in lanes] == [False, True]
    assert result["asymmetric"] is True
    notes = " ".join(result["notes"])
    assert notes.count("asymmetric routing") == 1
    assert "dev:r4" in notes
    assert "dev:r3" not in notes


def test_a_network_scoped_trace_without_reply_is_unchanged(graph):
    _split_source(graph)

    plain = path.trace(None, "10.0.0.0/24", "10.99.0.7", gateways=[GW])
    with_reply = path.trace(None, "10.0.0.0/24", "10.99.0.7", gateways=[GW], reply=True)

    assert set(plain) == {
        "hops",
        "legs",
        "verdict",
        "notes",
        "warnings",
        "indeterminate",
        "boundary",
        # where the walk left the estate, and where its paths end
        "left_estate",
        "reach",
    }
    assert with_reply["forward"] == plain


def test_a_single_forward_leg_answers_with_one_reply_object(graph):
    graph.routes = {
        "vrf:main": [
            _route("10.99.0.0/24", egress="eth2"),
            _route("10.0.0.0/24", egress="eth1"),
        ]
    }

    result = path.trace(None, "10.0.0.0/24", "10.99.0.7", gateways=[GW], reply=True)

    assert len(result["forward"]["legs"]) == 1
    assert isinstance(result["reply"], dict)
    assert result["reply"]["verdict"] == "reply: egress via eth1 (10.0.0.0/24, main table)"
    # shape parity with the list shape's own `destinations`
    assert result["reply"]["destinations"] == ["10.0.0.0/24"]


def test_the_reply_tuple_seeds_from_the_legs_own_source_partition():
    leg = {"sources": ["10.0.0.128/25"]}
    reply_src, reply_dst, lb_note = _build_reply_tuple(leg, _intervals(["10.0.0.0/24"]), DST)
    assert reply_src == DST
    assert reply_dst == _intervals(["10.0.0.128/25"])
    assert lb_note is None


def test_a_recorded_translation_still_outranks_the_legs_own_partition():
    """The seed is only what a leg with no translation reduces to: a leg whose
    sNAT the forward walk recorded replies to the pre-translation address that
    step names, not to the partition the leg carried downstream."""
    leg = {
        "sources": ["203.0.113.7/32"],
        "nat_chain": [
            _step(
                "dev:r1",
                "snat",
                pre_src=["10.0.0.128/25"],
                pre_dst=["8.8.8.8/32"],
                post_src=["203.0.113.7/32"],
                post_dst=["8.8.8.8/32"],
            )
        ],
    }
    dst = _intervals(["8.8.8.8/32"])
    reply_src, reply_dst, _lb = _build_reply_tuple(leg, _intervals(["10.0.0.0/24"]), dst)
    assert reply_src == dst
    assert reply_dst == _intervals(["10.0.0.128/25"])


# --- multi-part source NAT accumulates, never overwrites ---------------------------------


def test_a_claimed_snat_part_plus_an_untranslated_remainder_both_answer_the_reply():
    leg = {
        "sources": ["10.0.0.0/24"],
        "nat_chain": [
            _step(
                "dev:r1",
                "snat",
                pre_src=["10.0.0.0/25"],
                pre_dst=["8.8.8.8/32"],
                post_src=["203.0.113.7/32"],
                post_dst=["8.8.8.8/32"],
            )
        ],
    }
    dst = _intervals(["8.8.8.8/32"])
    reply_src, reply_dst, lb_note = _build_reply_tuple(leg, _intervals(["10.0.0.0/24"]), dst)
    assert reply_src == dst
    assert reply_dst == _intervals(["10.0.0.0/24"])
    assert lb_note is None


def test_two_claimed_snat_parts_at_the_same_device_both_answer_the_reply():
    leg = {
        "sources": ["10.0.0.0/24"],
        "nat_chain": [
            _step(
                "dev:r1",
                "snat",
                pre_src=["10.0.0.0/25"],
                pre_dst=["8.8.8.8/32"],
                post_src=["203.0.113.7/32"],
                post_dst=["8.8.8.8/32"],
                rule_uid="r1",
            ),
            _step(
                "dev:r1",
                "snat",
                pre_src=["10.0.0.128/25"],
                pre_dst=["8.8.8.8/32"],
                post_src=["203.0.113.8/32"],
                post_dst=["8.8.8.8/32"],
                rule_uid="r2",
            ),
        ],
    }
    dst = _intervals(["8.8.8.8/32"])
    reply_src, reply_dst, lb_note = _build_reply_tuple(leg, _intervals(["10.0.0.0/24"]), dst)
    assert reply_src == dst
    assert reply_dst == _intervals(["10.0.0.0/24"])
    assert lb_note is None


def test_vsx_reply_routes_to_hide_address_until_it_reaches_the_original_vs(graph):
    vs = dict(
        GW,
        dev_uid="dev:vsx",
        dev_name="vsx",
        firewall_instance_uid="fi:vs7",
        vsid=7,
        vsx_kind="virtual-system",
    )
    asr = {"dev_uid": "dev:asr", "dev_name": "asr", "if_uid": "if:asr-in", "if_name": "asr-in"}
    graph.sources = [_src_row()]
    graph.default_tables = {
        vs["if_uid"]: {"uid": "vrf:vs7"},
        "if:vs-out": {"uid": "vrf:vs7"},
        asr["if_uid"]: {"uid": "vrf:asr"},
        "if:asr-out": {"uid": "vrf:asr"},
    }
    graph.routes = {
        "vrf:vs7": [
            _route("203.0.113.0/24", egress="vs-out", next_hop="192.0.2.2"),
            _route("10.0.0.0/24", egress="eth1"),
        ],
        "vrf:asr": [
            _route("203.0.113.0/24", egress="asr-out"),
            _route("198.51.100.7/32", egress="asr-in", next_hop="192.0.2.1"),
        ],
    }
    for routes in graph.routes.values():
        routes.append(_route("192.0.2.0/24", egress="transit", kind="ORIGINATES"))
    graph.next_hop_devs = {"192.0.2.2": asr, "192.0.2.1": dict(vs, if_uid="if:vs-out", if_name="vs-out")}
    graph.nat_by_dev = {"dev:vsx": [_nat_row(orig_src_addrs=["10.0.0.0/24"], translation="198.51.100.7")]}
    graph.rb = _rb(default_action="accept")
    result = path.trace(None, "10.0.0.5", "203.0.113.10", gateways=[vs], reply=True)
    reply = result["reply"]
    assert any(h["kind"] == "FirewallInstance" and h["uid"] == "fi:vs7" for h in reply["hops"]), result
    assert any(h["label"] == "198.51.100.7/32" for h in reply["hops"])
    assert any(h["label"] == "10.0.0.0/24" for h in reply["hops"])
    assert any("undoes source translation" in (h.get("note") or "") for h in reply["hops"])
    assert not result["asymmetric"]
    assert reply["indeterminate"]  # runtime session/PAT allocation is not a configuration fact


def test_inverse_nat_cannot_cross_members_or_virtual_contexts():
    from hst.path import reply_nat

    chain = [
        _step(
            "member-a",
            "snat",
            ["10.0.0.5"],
            ["203.0.113.10"],
            ["198.51.100.7"],
            ["203.0.113.10"],
            context_uid="vs7",
        )
    ]
    assert reply_nat.point_chain(chain)
    translated = _intervals(["198.51.100.7"])
    for member, context in (("member-b", "vs7"), ("member-a", "vs8")):
        addresses, applied = reply_nat.undo(
            tuple(chain), device=member, context=context, stage="ingress", addresses=translated
        )
        assert addresses == translated and not applied
    addresses, applied = reply_nat.undo(
        tuple(chain), device="member-a", context="vs7", stage="ingress", addresses=translated
    )
    assert addresses == SRC and applied == [0]


def test_return_nat_undo_is_ordered_by_virtual_context_on_the_same_member():
    from hst.path import reply_nat

    chain = [
        _step(
            "member",
            "snat",
            ["10.0.0.5"],
            ["203.0.113.10"],
            ["192.0.2.7"],
            ["203.0.113.10"],
            context_uid="vs7",
        ),
        _step(
            "member",
            "snat",
            ["192.0.2.7"],
            ["203.0.113.10"],
            ["198.51.100.8"],
            ["203.0.113.10"],
            context_uid="vs8",
        ),
    ]
    src, dst = reply_nat.wire_reply(chain, SRC, DST)
    assert src == DST and dst == _intervals(["198.51.100.8"])
    dst, applied = reply_nat.undo(
        tuple(chain), device="member", context="vs8", stage="ingress", addresses=dst
    )
    assert dst == _intervals(["192.0.2.7"]) and applied == [1]
    dst, applied = reply_nat.undo(
        tuple(chain), device="member", context="vs7", stage="ingress", addresses=dst
    )
    assert dst == SRC and applied == [0]


def test_return_destination_nat_changes_source_at_egress_only():
    from hst.path import reply_nat

    chain = (
        _step(
            "member",
            "dnat",
            ["10.0.0.5"],
            ["198.51.100.8"],
            ["10.0.0.5"],
            ["203.0.113.10"],
            context_uid="vs7",
        ),
    )
    src, applied = reply_nat.undo(chain, device="member", context="vs7", stage="ingress", addresses=DST)
    assert src == DST and applied == []
    src, applied = reply_nat.undo(chain, device="member", context="vs7", stage="egress", addresses=DST)
    assert src == _intervals(["198.51.100.8"]) and applied == [0]


# --- the reply walk gets the forward walk's policy and gate safeguards ------------------


def test_a_reply_through_a_device_whose_policy_was_not_collected_is_undecided(graph, monkeypatch):
    """r2 is on the reply only; the pinned run was refused its running-config,
    so finding no gate there is not evidence the reply is admitted."""
    asked = []

    def evidence(_session, uid):
        asked.append(uid)
        return (["interface_config=unauthorized"], None) if uid == "dev:r2" else ([], None)

    monkeypatch.setattr(tracemod, "policy_evidence", evidence)
    graph.default_tables = {"if:r2-eth5": {"uid": "vrf:r2"}}
    graph.routes = {"vrf:r2": [_route("10.0.0.0/24", egress="r2-eth9", kind="ORIGINATES")]}
    terminal = {"dev_uid": "dev:r2", "dev_name": "r2", "if_uid": "if:r2-eth5", "if_name": "r2-eth5"}
    result = _walk_reply_leg(
        None, {}, terminal, ["dev:r1", "dev:r2"], {}, ORIG_SRC, ORIG_DST, None, max_hops=8
    )
    assert "dev:r2" in asked
    assert result["indeterminate"] is True
    assert "interface_config=unauthorized" in result["legs"][0]["indeterminate_reason"]
    assert any("interface_config=unauthorized" in w for w in result["warnings"])
    assert "policy of 1 device(s) not collected completely" in result["verdict"]


def test_a_gate_the_reply_walk_did_not_evaluate_makes_the_reply_undecided(graph, monkeypatch):
    monkeypatch.setattr(
        tracemod,
        "unevaluated_gates",
        lambda _session, uids, _evaluated: (
            [{"uid": "gate:x", "kind": "FutureGate", "name": "x"}] if "dev:r2" in uids else []
        ),
    )
    graph.default_tables = {"if:r2-eth5": {"uid": "vrf:r2"}}
    graph.routes = {"vrf:r2": [_route("10.0.0.0/24", egress="r2-eth9", kind="ORIGINATES")]}
    terminal = {"dev_uid": "dev:r2", "dev_name": "r2", "if_uid": "if:r2-eth5", "if_name": "r2-eth5"}
    result = _walk_reply_leg(
        None, {}, terminal, ["dev:r1", "dev:r2"], {}, ORIG_SRC, ORIG_DST, None, max_hops=8
    )
    assert result["indeterminate"] is True
    assert any("on path, not evaluated" in w for w in result["warnings"])
    assert "1 gate(s) not evaluated" in result["verdict"]


# --- a reply admitted from session state credits the rulebases it makes irrelevant -------


def _stateful_zoned_router(graph, monkeypatch, policy=("established=accept", "related=accept")):
    from hst.path.gates import firewall as fwmod

    _zoned_router(graph)
    graph.zone_rulebases_by_dev["dev:r1"] = [
        _zone_rb_row("rb:lan-guest", "lan", "guest"),
        _zone_rb_row("rb:guest-lan", "guest", "lan"),
        _zone_rb_row("rb:iot-lan", "iot", "lan"),
        _zone_rb_row("rb:lan-iot", "lan", "iot"),
    ]
    graph.gates = [
        {"uid": "rb:lan-guest", "name": "LAN-GUEST", "kind": "FwRulebase"},
        {"uid": "rb:guest-lan", "name": "GUEST-LAN", "kind": "FwRulebase"},
        {"uid": "rb:iot-lan", "name": "IOT-LAN", "kind": "FwRulebase"},
        {"uid": "rb:lan-iot", "name": "LAN-IOT", "kind": "FwRulebase"},
    ]
    graph.sources = [_src_row(ip="10.0.0.5")]
    monkeypatch.setattr(fwmod, "_device_state_policy", lambda session, dev: list(policy) if policy else None)


def _round_trip():
    return path.trace(
        None, "10.0.0.5", "10.0.40.9", port=443, proto="tcp", gateways=[GW_LAN, GW_GUEST], reply=True
    )


def test_a_reply_admitted_from_session_state_is_decided_on_a_device_with_zone_rule_sets(graph, monkeypatch):
    _stateful_zoned_router(graph, monkeypatch)

    result = _round_trip()

    assert result["forward"]["legs"][0]["blocked"] is False
    assert result["forward"]["indeterminate"] is False
    reply = result["reply"]
    leg = reply["legs"][0]
    assert str(leg["firewall"]).startswith("admitted from session state")
    assert leg["blocked"] is False
    assert reply["indeterminate"] is False
    assert not leg.get("indeterminate")
    assert reply["verdict"].startswith("reply: egress via eth1")
    assert "not evaluated" not in reply["verdict"]
    assert not any("not evaluated" in w for w in reply["warnings"])
    assert set(leg["fw_uids"]) >= {"rb:lan-guest", "rb:guest-lan", "rb:iot-lan", "rb:lan-iot"}


def test_a_session_state_reply_reports_a_gate_no_one_evaluated(graph, monkeypatch):
    """The admission credits rule sets only: a gate of another kind bound to
    the device stays in the safeguard's report and the reply is undecided. The
    same gate leaves the forward leg undecided, so the reply is not admitted
    from session state either: its admission is not established."""
    _stateful_zoned_router(graph, monkeypatch)
    graph.gates.append({"uid": "gate:x", "name": "x", "kind": "FutureGate"})

    reply = _round_trip()["reply"]

    assert str(reply["legs"][0]["firewall"]).startswith("session state admission not established")
    assert reply["indeterminate"] is True
    assert "FutureGate x: on path, not evaluated" in reply["warnings"]
    assert not any("FwRulebase" in w for w in reply["warnings"])


def test_a_session_state_reply_through_a_device_whose_policy_was_not_collected_is_undecided(
    graph, monkeypatch
):
    _stateful_zoned_router(graph, monkeypatch)
    monkeypatch.setattr(
        tracemod,
        "policy_evidence",
        lambda _session, uid: (["interface_config=unauthorized"], None) if uid == "dev:r1" else ([], None),
    )

    reply = _round_trip()["reply"]

    assert reply["indeterminate"] is True
    assert "policy of 1 device(s) not collected completely" in reply["verdict"]


def test_a_reply_not_admitted_from_state_keeps_the_full_coverage_check(graph, monkeypatch):
    _stateful_zoned_router(graph, monkeypatch, policy=None)
    graph.gates.append({"uid": "rb:stray", "name": "STRAY", "kind": "FwRulebase"})

    reply = _round_trip()["reply"]

    assert not str(reply["legs"][0].get("firewall", "")).startswith("admitted from session state")
    assert reply["indeterminate"] is True
    assert "FwRulebase STRAY: on path, not evaluated" in reply["warnings"]


def test_a_reply_the_state_policy_drops_is_a_decided_block(graph, monkeypatch):
    """The drop branch of the state policy credits the same rule sets: the
    reply is blocked, not undecided over rule sets the policy runs ahead of."""
    _stateful_zoned_router(graph, monkeypatch, policy=("established=drop",))

    reply = _round_trip()["reply"]

    assert reply["legs"][0]["blocked"] is True
    assert reply["indeterminate"] is False
    assert not any("not evaluated" in w for w in reply["warnings"])
