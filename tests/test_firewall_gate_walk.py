"""Each test runs the gate's own walk on rows in the shape `_RULEBASE_RULES` returns."""

# ruff: noqa: F811

from __future__ import annotations

from typing import Any

import pytest
from tests.test_path_reply import _round_trip, _stateful_zoned_router
from tests.test_path_trace import graph  # noqa: F401

from hst import path
from hst.path import DENY, INDETERMINATE, PERMIT, classify_action
from hst.path.addrsets import _ports, _protoset, _size
from hst.path.gates import firewall as fw
from hst.path.state import FlowRegion, Rect

SRC = path._intervals(["10.0.1.0/24"])
DST = path._intervals(["8.8.8.8/32"])


def _rule(pos: int, action: str, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "uid": f"r{pos}",
        "pos": pos,
        "action": action,
        "name": None,
        "out_if": None,
        "in_if": None,
        "states": [],
        "jump_target": None,
        "svc_any": True,
        "svc_negate": False,
        "protos": [],
        "ports": [],
        "svc_opaque": False,
        "svc_src_port": False,
        "svc_opaque_reasons": [],
        "svc_obj_count": 0,
        "src_ports": [],
        "src_any": True,
        "dst_any": True,
        "src_negate": False,
        "dst_negate": False,
        "src_cidrs": [],
        "src_ips": [],
        "src_ranges": [],
        "dst_cidrs": [],
        "dst_ips": [],
        "dst_ranges": [],
        "src_obj_count": 0,
        "dst_obj_count": 0,
        "src_opaque": False,
        "dst_opaque": False,
    }
    return {**base, **kw}


# --- a rule scoped to an interface on a side whose name did not resolve -------------

_FORWARD = {
    "rb_uid": "vyos:r1:ipv4:forward",
    "rb_name": "ipv4 forward filter",
    "vendor": "vyos",
    "af": 4,
    "chain": "forward",
    "default_action": "accept",
    "approximate": False,
}


def _forward_chain(monkeypatch, rules, names):
    name_rows = [{"uid": u, "name": n} for u, n in names.items()]
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(
        path,
        "_read",
        lambda s, q, **p: (
            [_FORWARD]
            if "ENFORCES" in q
            else name_rows
            if "i.uid IN" in q
            else rules
            if "HAS_RULE" in q
            else []
        ),
    )


def _device(out_if, chain="forward", port: Any = 443, proto: Any = "tcp", **kw):
    return path._device_rulebase_verdict(
        None, "dev:r1", "if:eth1", out_if, SRC, DST, port, proto, 4, chain=chain, **kw
    )


@pytest.mark.parametrize("scope", ["pppoe0", "!eth1"])
def test_an_outbound_scoped_drop_on_an_unresolved_egress_is_undecided(monkeypatch, scope):
    _forward_chain(monkeypatch, [_rule(10, "drop", out_if=scope), _rule(20, "accept")], {"if:eth1": "eth1"})
    v = _device(None)
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["pos"] == 10
    assert "egress interface name did not resolve" in v["indeterminate_reason"]
    assert repr(scope) in v["indeterminate_reason"]


def test_an_outbound_scoped_rule_on_an_unresolved_egress_is_undecided_on_a_range(monkeypatch):
    _forward_chain(
        monkeypatch, [_rule(10, "drop", out_if="pppoe0"), _rule(20, "accept")], {"if:eth1": "eth1"}
    )
    regions = _device(None, port="80,443")
    assert regions
    assert {classify_action(r["action"]) for r in regions} == {INDETERMINATE}


def test_an_interface_scoped_rule_with_resolved_names_is_decided(monkeypatch):
    rules = [_rule(10, "drop", out_if="pppoe0"), _rule(20, "accept")]
    _forward_chain(monkeypatch, rules, {"if:eth1": "eth1", "if:pppoe0": "pppoe0", "if:eth2": "eth2"})
    hit = _device("if:pppoe0")
    assert (classify_action(hit["action"]), hit["pos"]) == (DENY, 10)
    miss = _device("if:eth2")
    assert (classify_action(miss["action"]), miss["pos"]) == (PERMIT, 20)


def test_a_rule_whose_addresses_miss_is_skipped_whatever_its_interface_scope(monkeypatch):
    other = path._intervals(["192.0.2.0/24"])
    rules = [
        _rule(10, "drop", out_if="pppoe0", src_any=False, src_obj_count=1, src_cidrs=["192.0.2.0/24"]),
        _rule(20, "accept"),
    ]
    _forward_chain(monkeypatch, rules, {"if:eth1": "eth1"})
    assert other != SRC
    v = _device(None)
    assert (classify_action(v["action"]), v["pos"]) == (PERMIT, 20)


def test_an_outbound_scope_on_the_input_chain_is_a_plain_miss(monkeypatch):
    """A packet the router terminates leaves by no interface: an outbound
    scope does not govern it, which is not an unresolved name."""
    _forward_chain(
        monkeypatch, [_rule(10, "drop", out_if="pppoe0"), _rule(20, "accept")], {"if:eth1": "eth1"}
    )
    monkeypatch.setitem(_FORWARD, "chain", "input")
    v = _device(None, chain="input")
    assert (classify_action(v["action"]), v["pos"]) == (PERMIT, 20)


def test_an_inbound_scope_on_an_ingress_with_no_name_is_undecided(monkeypatch):
    _forward_chain(monkeypatch, [_rule(10, "drop", in_if="eth1"), _rule(20, "accept")], {"if:out": "eth0"})
    v = _device("if:out")
    assert classify_action(v["action"]) == INDETERMINATE
    assert "ingress interface name did not resolve" in v["indeterminate_reason"]


def test_the_walk_with_no_unresolved_side_reads_a_missing_name_as_a_miss():
    """A caller that names no unresolved side (the local zone read, the leak
    guard) keeps `_iface_name_matches`'s reading of a missing name."""
    rules = [_rule(10, "drop", out_if="pppoe0"), _rule(20, "accept")]
    m = fw._first_match_point(rules, "eth1", None, SRC, DST, 443, "tcp")
    assert m is not None and m[0]["pos"] == 20


# --- one target rule reached by two jump rules -------------------------------------


def _two_jumps():
    target = _rule(1, "accept", uid="WEB:1")
    j1 = _rule(10, "jump", uid="FWD:10", svc_any=False, svc_obj_count=1, protos=["tcp"], ports=["80"])
    j2 = _rule(
        20,
        "jump",
        uid="FWD:20",
        svc_any=False,
        svc_obj_count=1,
        protos=["tcp"],
        ports=["443"],
        src_any=False,
        src_obj_count=1,
        src_cidrs=["10.0.1.0/25"],
    )
    return [fw._jump_scoped(j1, target, "WEB"), fw._jump_scoped(j2, target, "WEB"), _rule(30, "drop")]


def test_one_target_rule_reached_by_two_jumps_keeps_two_regions():
    regions = fw._first_match_regions(_two_jumps(), "a", "b", SRC, DST, _protoset(["tcp"]), _ports("80,443"))
    by_port = {
        tuple((lo, hi) for _f, lo, hi in q): (r["pos"], _size(sh)) for r, sh, _dh, _p, q in regions if r
    }
    assert by_port[((80, 80),)] == (10, 256)
    assert by_port[((443, 443),)] == (20, 128)


def test_a_partial_jump_region_reads_partial_through_the_device_verdict(monkeypatch):
    _forward_chain(monkeypatch, _two_jumps(), {"if:eth1": "eth1", "if:eth0": "eth0"})
    regions = _device("if:eth0", port="80,443")
    https = next(r for r in regions if r["port_subset"] == [(0, 443, 443)])
    http = next(r for r in regions if r["port_subset"] == [(0, 80, 80)])
    assert https["partial"] is True and https["pos"] == 20
    assert http["partial"] is False and http["pos"] == 10


def test_regions_one_rule_decided_alike_merge():
    rules = [_rule(1, "accept", svc_any=False, svc_obj_count=2, protos=["tcp", "tcp"], ports=["442", "443"])]
    regions = fw._first_match_regions(rules, "a", "b", SRC, DST, _protoset(["tcp"]), _ports("442-443"))
    decided = [r for r in regions if r[0] is not None]
    assert len(decided) == 1 and decided[0][4] == [(0, 442, 443)]


# --- a negated service with no service member --------------------------------------


def _negated_empty():
    return [_rule(3, "drop", svc_any=False, svc_negate=True, svc_obj_count=0), _rule(4, "accept")]


def test_a_negated_service_with_no_member_is_undecided_on_the_point_path():
    m = fw._first_match_point(_negated_empty(), "a", "b", SRC, DST, 443, "tcp")
    assert m is not None
    assert (m[0]["pos"], classify_action(m[0]["action"])) == (3, INDETERMINATE)
    assert m[0]["indeterminate_reason"] == fw._NEGATED_EMPTY_SERVICE_REASON


def test_a_negated_service_with_no_member_is_undecided_on_the_region_path():
    regions = fw._first_match_regions(
        _negated_empty(), "a", "b", SRC, DST, _protoset(["tcp"]), _ports("80-443")
    )
    assert [(r["pos"], classify_action(r["action"])) for r, *_ in regions] == [(3, INDETERMINATE)]


def test_a_negated_service_with_members_decides():
    rules = [
        _rule(3, "drop", svc_any=False, svc_negate=True, svc_obj_count=1, protos=["tcp"], ports=["443"]),
        _rule(4, "accept"),
    ]
    assert fw._first_match_point(rules, "a", "b", SRC, DST, 443, "tcp")[0]["pos"] == 4
    assert classify_action(fw._first_match_point(rules, "a", "b", SRC, DST, 80, "tcp")[0]["action"]) == DENY


# --- a service group's own node on a source-port slice -----------------------------


def _group_rule():
    return _rule(
        1,
        "accept",
        svc_any=False,
        svc_src_port=True,
        svc_obj_count=1,
        protos=[None, "tcp"],
        ports=[None, "443"],
        src_ports=[None, "1000"],
    )


def test_a_group_node_alone_on_a_slice_its_members_miss_is_a_miss():
    assert fw._rule_on_sport_slice(_group_rule(), _ports("2000")) is None


def test_a_group_rule_whose_member_misses_the_slice_does_not_decide_it():
    sliced = fw._first_match_by_sport(
        [_group_rule(), _rule(2, "drop")],
        "a",
        "b",
        SRC,
        DST,
        _protoset(["tcp"]),
        _ports("443"),
        tuple(_ports("2000")),
    )
    ((_slice, regions),) = sliced
    assert [(r["pos"], classify_action(r["action"])) for r, *_ in regions] == [(2, DENY)]


def test_a_group_rule_whose_member_covers_the_slice_matches():
    on = fw._rule_on_sport_slice(_group_rule(), _ports("1000"))
    assert on is not None and on["protos"] == [None, "tcp"] and on["ports"] == [None, "443"]
    m = fw._first_match_point([on, _rule(2, "drop")], "a", "b", SRC, DST, 443, "tcp")
    assert (m[0]["pos"], classify_action(m[0]["action"])) == (1, PERMIT)


def test_a_group_rule_with_an_opaque_member_stays_undecided_on_the_slice():
    on = fw._rule_on_sport_slice({**_group_rule(), "svc_opaque": True}, _ports("2000"))
    assert on is not None
    m = fw._first_match_point([on, _rule(2, "drop")], "a", "b", SRC, DST, 443, "tcp")
    assert classify_action(m[0]["action"]) == INDETERMINATE


# --- the outbound interface ACL on a region leg ------------------------------------


class _Trail:
    def __init__(self):
        self.notes: list[str] = []
        self.warnings: list[str] = []

    def hop(self, *a, **kw):
        pass

    def warn(self, text):
        self.warnings.append(text)


def test_an_outbound_acl_that_covers_one_rectangle_in_part_is_not_a_confirmed_permit(monkeypatch):
    """IOS-XE outbound list: tcp/80-81 permitted for every source,
    tcp/443-444 only for 10.0.1.0/25; the rest falls to the implicit deny."""
    acl = {
        "rb_uid": "cisco:edge-out",
        "rb_name": "EDGE-OUT",
        "vendor": "cisco",
        "match_context": "interface-acl",
        "default_action": "deny",
        "approximate": False,
        "acl_bindings": [["Gi0/2", "out"]],
    }
    rules = [
        _rule(10, "permit", svc_any=False, svc_obj_count=1, protos=["tcp"], ports=["80-81"]),
        _rule(
            20,
            "permit",
            svc_any=False,
            svc_obj_count=1,
            protos=["tcp"],
            ports=["443-444"],
            src_any=False,
            src_obj_count=1,
            src_cidrs=["10.0.1.0/25"],
        ),
    ]
    names = [{"uid": "if:in", "name": "Gi0/1"}, {"uid": "if:out", "name": "Gi0/2"}]
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(
        path,
        "_read",
        lambda s, q, **p: (
            [acl] if "ENFORCES" in q else names if "i.uid IN" in q else rules if "HAS_RULE" in q else []
        ),
    )
    region = FlowRegion(
        [
            Rect(
                af=4,
                src=tuple(SRC),
                dst=tuple(DST),
                proto=frozenset({6}),
                dport=tuple(_ports("80-81")),
                sport=None,
            ),
            Rect(
                af=4,
                src=tuple(SRC),
                dst=tuple(DST),
                proto=frozenset({6}),
                dport=tuple(_ports("443-444")),
                sport=None,
            ),
        ]
    )
    leg: dict[str, Any] = {}
    gw = {"dev_uid": "dev:fw1", "if_uid": "if:in"}
    route = {"egress_uid": "if:out", "egress_name": "Gi0/2"}
    outcome = fw._apply_egress_acl(None, _Trail(), leg, gw, route, SRC, DST, 80, "tcp", "src", region=region)
    assert outcome == INDETERMINATE
    assert leg["indeterminate"] is True


# --- a hop no rule set judged, on a router with a global state policy --------------


def test_the_reply_through_a_hop_no_rule_set_judged_is_not_admitted_from_session_state(graph, monkeypatch):
    """VyOS with zones and `established=accept`: the forward leg's egress is in
    no zone, so no rule set judges the hop and the leg is undecided. The hop
    records a permit with no policy; the reply must not read it as a
    confirmed permit and admit itself from session state."""
    _stateful_zoned_router(graph, monkeypatch)
    graph.ingress_zones = {"if:eth1": "lan"}
    graph.zone_pairs.pop(("if:eth1", "if:eth1.40"))

    result = _round_trip()

    assert result["forward"]["indeterminate"] is True
    assert "the egress interface is in no zone" in " ".join(result["forward"]["warnings"])
    leg = result["reply"]["legs"][0]
    assert not str(leg.get("firewall")).startswith("admitted from session state")
    assert str(leg.get("firewall")).startswith("session state admission not established")
    assert result["reply"]["indeterminate"] is True


# --- a rectangle with one protocol and one port (one flow) -------------------------


def _one_flow_rect():
    return Rect(
        af=4, src=tuple(SRC), dst=tuple(DST), proto=frozenset({6}), dport=tuple(_ports("443")), sport=None
    )


def test_the_outbound_acl_reads_a_one_protocol_one_port_rectangle(monkeypatch):
    """A region leg's rectangle for one tcp/443 flow holds the protocol as the
    number 6."""
    acl = {
        "rb_uid": "cisco:edge-out",
        "rb_name": "EDGE-OUT",
        "vendor": "cisco",
        "match_context": "interface-acl",
        "default_action": "deny",
        "approximate": False,
        "acl_bindings": [["Gi0/2", "out"]],
    }
    rules = [_rule(10, "permit", svc_any=False, svc_obj_count=1, protos=["tcp"], ports=["443"])]
    names = [{"uid": "if:in", "name": "Gi0/1"}, {"uid": "if:out", "name": "Gi0/2"}]
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(
        path,
        "_read",
        lambda s, q, **p: (
            [acl] if "ENFORCES" in q else names if "i.uid IN" in q else rules if "HAS_RULE" in q else []
        ),
    )
    leg: dict[str, Any] = {}
    gw = {"dev_uid": "dev:fw1", "if_uid": "if:in"}
    route = {"egress_uid": "if:out", "egress_name": "Gi0/2"}
    region = FlowRegion((_one_flow_rect(),))
    outcome = fw._apply_egress_acl(None, _Trail(), leg, gw, route, SRC, DST, 443, "tcp", "src", region=region)
    assert outcome == PERMIT
    assert not leg.get("indeterminate")


@pytest.mark.parametrize(("action", "kinds"), [("accept", {"pass"}), ("drop", {"deny"})])
def test_the_impact_local_filter_reads_a_one_protocol_one_port_rectangle(monkeypatch, action, kinds):
    """An accept leaves the packet to the local zone read."""
    from hst.impact.evaluate import _LocalFilter

    chain = {**_FORWARD, "rb_uid": "vyos:r1:ipv4:input", "chain": "input", "default_action": "drop"}
    rules = [_rule(10, action, svc_any=False, svc_obj_count=1, protos=["tcp"], ports=["443"])]
    names = [{"uid": "if:eth1", "name": "eth1"}]
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(
        path,
        "_read",
        lambda s, q, **p: (
            [chain] if "ENFORCES" in q else names if "i.uid IN" in q else rules if "HAS_RULE" in q else []
        ),
    )
    out = _LocalFilter(None, "dev:r1", "if:eth1", None, chain="input").apply(FlowRegion((_one_flow_rect(),)))
    assert {effect.kind for _part, effect in out} == kinds
