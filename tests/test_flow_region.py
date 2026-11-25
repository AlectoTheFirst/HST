"""The tests pin `FlowRegion` and the gate transitions built on it (`hst.path.state`)."""

# ruff: noqa: F811

from tests.test_path_nat import _dnat_row, _nat_row
from tests.test_path_trace import GW, _lb_member, _lb_vs, _route, _rule, _src_row, graph  # noqa: F401

from hst import path
from hst.path.addrsets import _PORT_FAMILY, _intervals, _ports
from hst.path.gates import Stage, _Trail
from hst.path.gates.firewall import _SRC_PORT_REASON, FirewallTransition
from hst.path.gates.lb import _VIP_NO_SERVICE_REASON, _VIP_UNEVALUATED_KIND_REASON, LbTransition
from hst.path.gates.nat import NatTransition, _nat_stage_rules
from hst.path.gates.pbr import PbrTransition, _pbr_partition
from hst.path.gates.routing import RoutingTransition
from hst.path.gates.zpa import ZpaTransition
from hst.path.state import FlowRegion, Predicate, Rect, claim, compose, pipeline
from hst.path.verdict import DENY, INDETERMINATE, PERMIT

TCP = frozenset({6})


def _region(src="10.0.0.5", dst="203.0.113.10", proto=TCP, port="1-1024", sport=None):
    return FlowRegion.from_query(
        _intervals([src]),
        _intervals([dst]),
        proto,
        None if port is None else _ports(port),
        None if sport is None else _ports(sport),
    )


def _rb(default_action="accept"):
    return {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": default_action,
        "approximate": False,
    }


def _ivals(spec):
    return tuple(_ports(spec))


# --- the rectangle algebra ----------------------------------------------------------------


class TestRectAlgebra:
    def test_from_query_keeps_an_unstated_dimension_none(self):
        region = _region(proto=None, port="443", sport=None)
        assert len(region) == 1
        rect = region.rects[0]
        assert rect.af == 4
        assert rect.proto is None
        assert rect.dport == ((_PORT_FAMILY, 443, 443),)
        assert rect.sport is None
        assert rect.stated() == frozenset({"dport"})

    def test_intersect_and_subtract_partition_the_rectangle(self):
        whole = _region().rects[0]
        part = whole.narrow(dport=_ivals("443"))
        assert whole.intersect(part) == part
        pieces = whole.subtract(part)
        assert len(pieces) == 1
        assert pieces[0].dport == ((_PORT_FAMILY, 1, 442), (_PORT_FAMILY, 444, 1024))
        # the pieces and the part together are the whole again, and nothing
        # of the part is left in the pieces
        assert FlowRegion(pieces).intersect(FlowRegion.single(part)).is_empty()
        assert FlowRegion.single(whole).subtract(FlowRegion(pieces)).rects == (part,)

    def test_a_disjoint_intersection_is_empty(self):
        a = _region(port="1-100")
        b = _region(port="200-300")
        assert a.intersect(b).is_empty()
        assert a.subtract(b).rects == a.rects

    def test_union_keeps_two_rectangles_and_not_their_bounding_box(self):
        a = _region(src="10.0.0.0/25", port="80").rects[0]
        b = _region(src="10.0.0.128/25", port="443").rects[0]
        union = FlowRegion.single(a).union(FlowRegion.single(b))
        assert union.rects == (a, b)
        crossed = a.narrow(dport=b.dport)
        assert union.intersect(FlowRegion.single(crossed)).is_empty()

    def test_claim_is_three_valued_per_dimension(self):
        rect = _region(proto=None, port="1-1024").rects[0]
        c = claim(rect, Predicate(proto=TCP, dport=_ivals("443")))
        assert c.unknown == frozenset({"proto"})
        assert c.hit is not None
        assert c.hit.proto is None
        assert c.hit.dport == _ivals("443")
        assert [r.dport for r in c.rest] == [((_PORT_FAMILY, 1, 442), (_PORT_FAMILY, 444, 1024))]
        miss = claim(rect, Predicate(src=tuple(_intervals(["192.168.0.0/16"]))))
        assert miss.hit is None
        assert miss.rest == (rect,)

    def test_claim_carves_the_remainder_in_dimension_order(self):
        rect = _region(src="10.0.0.0/24", port="1-1024").rects[0]
        c = claim(rect, Predicate(src=tuple(_intervals(["10.0.0.0/25"])), dport=_ivals("443")))
        assert c.hit is not None
        assert c.hit.src == tuple(_intervals(["10.0.0.0/25"]))
        assert c.hit.dport == _ivals("443")
        assert len(c.rest) == 2
        other_half, other_ports = c.rest
        assert other_half.src == tuple(_intervals(["10.0.0.128/25"]))
        assert other_half.dport == rect.dport
        assert other_ports.src == c.hit.src
        assert other_ports.dport == ((_PORT_FAMILY, 1, 442), (_PORT_FAMILY, 444, 1024))

    def test_rewrite_records_the_request_and_narrow_keeps_it(self):
        rect = _region().rects[0]
        narrowed = rect.narrow(dport=_ivals("443"))
        assert narrowed.request is narrowed
        rewritten = narrowed.rewrite(dst=tuple(_intervals(["10.0.0.99"])))
        assert rewritten.request == narrowed
        again = rewritten.rewrite(dst=tuple(_intervals(["10.0.0.100"])))
        assert again.request == narrowed
        # equality is over the flows a rectangle covers, not over its history
        assert rewritten == again.narrow(dst=rewritten.dst)


# --- composition order ---------------------------------------------------------------------


class TestCompositionOrder:
    """`compose` applies transitions in the order given, and the order is the
    answer: a filter written on the address a NAT rule rewrites to decides
    the flow when it runs after the rewrite and not when it runs before."""

    def _gates(self, graph):
        nat = NatTransition(_nat_stage_rules([_dnat_row()], "dnat", "eth1"))
        graph.rb = _rb("accept")
        graph.rules = [_rule(uid="cp:deny", pos=1, action="drop", dst_any=False, dst_cidrs=["10.0.0.99/32"])]
        fw = FirewallTransition(None, "dev:r1", "if:eth1", "if:eth0")
        return nat, fw

    def test_nat_then_policy_differs_from_policy_then_nat(self, graph):
        nat, fw = self._gates(graph)
        region = _region()
        nat_then_fw = compose(region, [nat, fw])
        fw_then_nat = compose(region, [fw, nat])
        assert [[e.kind for e in effects] for _r, effects in nat_then_fw] == [["rewrite", DENY]]
        assert [[e.kind for e in effects] for _r, effects in fw_then_nat] == [[PERMIT, "rewrite"]]
        assert nat_then_fw[0][1][-1].terminal
        assert not fw_then_nat[0][1][-1].terminal
        # both compositions end on the translated destination, and both keep
        # the request the caller stated as the origin of what they answer for
        for _reg, _effects in (*nat_then_fw, *fw_then_nat):
            assert _reg.rects[0].dst == tuple(_intervals(["10.0.0.99"]))
            assert _reg.rects[0].request.dst == tuple(_intervals(["203.0.113.10"]))

    def test_the_pipeline_order_is_read_off_the_stage_model(self, graph):
        nat, fw = self._gates(graph)
        assert pipeline({Stage.FILTER_RB: fw, Stage.DNAT: nat}) == (nat, fw)
        assert pipeline({Stage.DNAT: nat, Stage.FILTER_RB: fw}) == (nat, fw)

    def test_a_terminal_effect_ends_its_branch(self, graph):
        nat, fw = self._gates(graph)
        branches = compose(_region(), [nat, fw, nat])
        assert [[e.kind for e in effects] for _r, effects in branches] == [["rewrite", DENY]]


# --- correlation ---------------------------------------------------------------------------


class TestCorrelationSurvivesNat:
    def test_a_two_rectangle_region_after_nat_is_not_its_bounding_box(self):
        rules = _nat_stage_rules(
            [
                _nat_row(
                    orig_src_raw="10.0.0.0/25",
                    translation="203.0.113.7",
                    xlate_src_addrs=["203.0.113.7"],
                    out_if="eth0",
                )
            ],
            "snat",
            "eth0",
        )
        low = _region(src="10.0.0.0/25", port="80").rects[0]
        high = _region(src="10.0.0.128/25", port="443").rects[0]
        out = NatTransition(rules).apply(FlowRegion((low, high)))
        rects = [reg.rects[0] for reg, _e in out]
        assert len(rects) == 2
        translated = next(r for r in rects if r.src == tuple(_intervals(["203.0.113.7"])))
        untouched = next(r for r in rects if r.src == high.src)
        assert translated.dport == _ivals("80")
        assert untouched.dport == _ivals("443")
        # the translated source never pairs with the other rectangle's port
        box = Rect(4, translated.src + untouched.src, low.dst, TCP, _ivals("80,443"), None)
        for r in rects:
            assert r != box
        assert translated.request == low
        assert untouched.request is untouched
        kinds = {reg.rects[0].src: e.kind for reg, e in out}
        assert kinds[translated.src] == "rewrite"
        assert kinds[untouched.src] == "pass"


# --- a stated source port ------------------------------------------------------------------


def _sport_rule(**kw):
    return _rule(
        uid="cp:ok",
        pos=1,
        action="accept",
        svc_any=False,
        protos=["tcp"],
        ports=["443"],
        svc_src_port=True,
        src_ports=["1024-65535"],
        **kw,
    )


class TestStatedSourcePortDecides:
    def _fw(self, graph):
        graph.rb = _rb("drop")
        graph.rules = [_sport_rule()]
        return FirewallTransition(None, "dev:r1", "if:eth1", "if:eth0")

    def test_a_source_port_inside_the_rule_range_is_a_confident_match(self, graph):
        fw = self._fw(graph)
        out = fw.apply(_region(port="443", sport="40000"))
        assert len(out) == 1
        reg, effect = out[0]
        assert effect.kind == PERMIT
        assert effect.data["by"] == "rule"
        assert effect.unknown == frozenset()
        assert reg.rects[0].sport == _ivals("40000")

    def test_a_source_port_outside_the_rule_range_is_a_confident_miss(self, graph):
        fw = self._fw(graph)
        out = fw.apply(_region(port="443", sport="80"))
        assert len(out) == 1
        _reg, effect = out[0]
        assert effect.kind == DENY
        assert effect.data["by"] == "default-action"

    def test_a_source_port_range_straddling_the_rule_splits_into_two_regions(self, graph):
        fw = self._fw(graph)
        out = fw.apply(_region(port="443", sport="1-65535"))
        by_sport = {reg.rects[0].sport: effect for reg, effect in out}
        assert by_sport[_ivals("1024-65535")].kind == PERMIT
        assert by_sport[_ivals("1-1023")].kind == DENY
        assert len(out) == 2

    def test_an_unstated_source_port_keeps_the_undecided_answer(self, graph):
        fw = self._fw(graph)
        out = fw.apply(_region(port="443", sport=None))
        assert len(out) == 1
        reg, effect = out[0]
        assert effect.kind == INDETERMINATE
        assert effect.reason == _SRC_PORT_REASON
        assert effect.unknown == frozenset({"sport"})
        assert reg.rects[0].sport is None

    def test_a_trace_stating_a_source_port_decides_the_rule(self, graph):
        graph.sources = [_src_row()]
        graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
        graph.rb = _rb("drop")
        graph.rules = [_sport_rule()]

        inside = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", src_port=40000, gateways=[GW])
        leg = inside["legs"][0]
        assert len(inside["legs"]) == 1
        assert not leg["blocked"] and not leg["indeterminate"]
        assert "by rule 1" in leg["firewall"]
        assert leg["service"] == {"proto": ["tcp"], "ports": [[443, 443]], "src_ports": [[40000, 40000]]}
        assert "from port 40000" in inside["verdict"]

        outside = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", src_port=80, gateways=[GW])
        assert outside["legs"][0]["blocked"]
        assert "default-action" in outside["legs"][0]["firewall"]

        unstated = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
        assert unstated["legs"][0]["indeterminate"]
        assert any(_SRC_PORT_REASON in w for w in unstated["warnings"])
        assert "service" not in unstated["legs"][0]

    def test_a_pbr_rule_scoped_to_a_source_port_is_decided_on_a_region(self, graph):
        graph.pbr = [
            {
                "pol_uid": "pol:1",
                "pol_name": "steer",
                "rule_uid": "rule:10",
                "pos": 10,
                "rule_name": None,
                "src_cidrs": [],
                "src_ips": [],
                "src_ranges": [],
                "dst_cidrs": [],
                "dst_ips": [],
                "dst_ranges": [],
                "table_uid": "vrf:100",
                "table_name": "100",
                "svc_obj_count": 1,
                "svc_protos": ["tcp"],
                "svc_port_specs": ["443"],
                "svc_opaque": False,
                "svc_opaque_reasons": [],
                "svc_src_port": True,
                "svc_src_ports": ["1024-65535"],
            }
        ]
        src, dst = _intervals(["10.0.0.5"]), _intervals(["8.8.8.8"])

        inside = _pbr_partition(
            None, _Trail(), "if:eth1", src, dst, service=(TCP, _ivals("443"), _ivals("40000"))
        )
        assert [(g["table_name"], g["opaque"]) for g in inside] == [("100", False)]
        assert inside[0]["sport_subset"] == _ivals("40000")

        outside = _pbr_partition(
            None, _Trail(), "if:eth1", src, dst, service=(TCP, _ivals("443"), _ivals("80"))
        )
        assert [g["table_name"] for g in outside] == ["default"]

        unstated = _pbr_partition(None, _Trail(), "if:eth1", src, dst, service=(TCP, _ivals("443"), None))
        assert [(g["table_name"], g["opaque"], g["opaque_reason"]) for g in unstated] == [
            ("100", True, _SRC_PORT_REASON)
        ]

        # the same answer through the transition, with the region narrowed to
        # what each group answers for
        out = PbrTransition(None, _Trail(), "if:eth1").apply(
            _region(dst="8.8.8.8", port="443", sport="1-65535")
        )
        by_sport = {reg.rects[0].sport: effect for reg, effect in out}
        assert by_sport[_ivals("1024-65535")].data["table_name"] == "100"
        assert by_sport[_ivals("1-1023")].data["table_name"] == "default"


# --- an unknown dimension survives composition --------------------------------------------


class TestUnknownDimensionSurvivesComposition:
    def test_an_unstated_protocol_stays_unstated_and_unknown_through_nat_and_policy(self, graph):
        nat = NatTransition(_nat_stage_rules([_dnat_row(protocol="tcp")], "dnat", "eth1"))
        graph.rb = _rb("accept")
        graph.rules = [
            _rule(uid="cp:svc", pos=1, action="drop", svc_any=False, protos=["tcp"], ports=["443"])
        ]
        fw = FirewallTransition(None, "dev:r1", "if:eth1", "if:eth0")
        branches = compose(_region(proto=None, port="443"), [nat, fw])
        assert branches
        for reg, effects in branches:
            assert all(r.proto is None for r in reg.rects)
            nat_effect, fw_effect = effects
            assert nat_effect.kind == "rewrite"
            assert "proto" in nat_effect.unknown
            assert nat_effect.data["rule"]["opaque"]
            assert fw_effect.kind == INDETERMINATE
            assert fw_effect.unknown == frozenset({"proto"})

    def test_claim_never_invents_a_value_for_an_unstated_dimension(self):
        rect = _region(proto=None, port=None, sport=None).rects[0]
        c = claim(rect, Predicate(proto=TCP, dport=_ivals("443"), sport=_ivals("1024-65535")))
        assert c.unknown == frozenset({"proto", "dport", "sport"})
        assert c.hit == rect
        assert c.rest == ()


# --- the remaining transitions -------------------------------------------------------------


class TestRoutingTransition:
    def test_longest_prefix_match_partitions_the_destination(self):
        routes = [_route("10.0.0.0/24", egress="eth2"), _route("0.0.0.0/0", egress="eth0")]
        out = RoutingTransition(routes).apply(_region(dst="10.0.0.0/23"))
        by_dst = {reg.rects[0].dst: effect for reg, effect in out}
        assert by_dst[tuple(_intervals(["10.0.0.0/24"]))].data["routes"][0]["egress_name"] == "eth2"
        assert by_dst[tuple(_intervals(["10.0.1.0/24"]))].data["routes"][0]["egress_name"] == "eth0"
        assert all(e.kind == "select" and not e.terminal for e in by_dst.values())

    def test_no_route_is_terminal(self):
        out = RoutingTransition([]).apply(_region())
        assert [(e.kind, e.terminal) for _r, e in out] == [("no-route", True)]


class TestLbTransition:
    def test_a_vip_relates_the_claimed_slice_to_its_member_and_names_the_rest(self, graph):
        graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]
        out = LbTransition(None, "dev:r1", [_lb_vs()], "10.0.30.10").apply(
            _region(dst="10.0.30.10", port="1-1024")
        )
        related = [(reg, e) for reg, e in out if e.kind == "relate"]
        rest = [(reg, e) for reg, e in out if e.kind == DENY]
        assert len(related) == 1 and len(rest) == 1
        member = related[0][0].rects[0]
        assert member.dst == tuple(_intervals(["10.0.10.5"]))
        assert member.dport == _ivals("8443")
        assert member.sport is None
        assert member.request.dst == tuple(_intervals(["10.0.30.10"]))
        assert member.request.dport == _ivals("443")
        # the one VirtualService on the VIP is of an evaluated kind and misses
        # the rest, so nothing on the VIP serves it: the walk blocks it there
        assert rest[0][0].rects[0].dport == ((_PORT_FAMILY, 1, 442), (_PORT_FAMILY, 444, 1024))
        assert rest[0][1].terminal and rest[0][1].reason == _VIP_NO_SERVICE_REASON

    def test_a_flow_no_vip_serves_is_blocked_as_the_walk_blocks_it(self, graph):
        graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]
        out = LbTransition(None, "dev:r1", [_lb_vs()], "10.0.30.10").apply(
            _region(dst="10.0.30.10", port="80")
        )
        assert [(e.kind, e.terminal, e.reason) for _r, e in out] == [(DENY, True, _VIP_NO_SERVICE_REASON)]
        assert out[0][1].data["vip"] == "10.0.30.10"

    def test_a_miss_beside_an_unevaluated_kind_stays_indeterminate(self, graph):
        graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]
        other = _lb_vs(uid="vs:gslb", name="gslb", kind="gslb", port=53)
        out = LbTransition(None, "dev:r1", [_lb_vs(), other], "10.0.30.10").apply(
            _region(dst="10.0.30.10", port="80")
        )
        assert [(e.kind, e.terminal) for _r, e in out] == [(INDETERMINATE, False)]
        assert out[0][1].reason == _VIP_UNEVALUATED_KIND_REASON

    def test_strict_mode_decides_a_known_miss_the_same_way(self, graph):
        graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]
        out = LbTransition(None, "dev:r1", [_lb_vs()], "10.0.30.10", require_known_health=True).apply(
            _region(dst="10.0.30.10", port="80")
        )
        assert [(e.kind, e.terminal, e.reason) for _r, e in out] == [(DENY, True, _VIP_NO_SERVICE_REASON)]

    def test_the_walk_names_the_part_of_a_range_no_vip_claims(self, graph):
        graph.sources = [_src_row()]
        graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
        graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs()
        graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]
        graph.routes["vrf:main"].append(_route("10.0.10.0/24", egress="eth3", kind="ORIGINATES"))

        result = path.trace(None, "10.0.0.5", "10.0.30.10", port="400-500", proto="tcp", gateways=[GW])

        legs = result["legs"]
        served = [ll for ll in legs if not ll["blocked"]]
        unclaimed = [ll for ll in legs if ll["blocked"]]
        assert len(served) == 1 and len(unclaimed) == 1
        assert not unclaimed[0]["indeterminate"]
        assert served[0]["service"] == {"proto": ["tcp"], "ports": [[8443, 8443]]}
        assert unclaimed[0]["service"] == {"proto": ["tcp"], "ports": [[400, 442], [444, 500]]}
        assert any("no virtual service on VIP 10.0.30.10 serves" in n for n in result["notes"])


class TestZpaTransition:
    IDENTITY = "idg:1"
    SEGMENT = "seg:1"

    def _broker(self, graph):
        graph.segment_ports[self.SEGMENT] = {"tcp": ["443", "443"], "udp": None}
        graph.access_rules[(self.IDENTITY, self.SEGMENT)] = [
            {
                "uid": "r:1",
                "name": "allow-web",
                "position": 1,
                "action": "ALLOW",
                "applies_to_all_identities": False,
                "conditions": None,
                "identity_named": True,
            }
        ]
        graph.segment_resolution[self.SEGMENT] = [{"addr": "10.0.20.5"}]
        graph.zpa_connectors[self.SEGMENT] = [{"uid": "conn:1", "name": "c1", "health": "up"}]
        graph.connector_address["conn:1"] = [{"host_uid": "vm:1", "ip": "10.0.0.7"}]
        return ZpaTransition(None, self.IDENTITY, self.SEGMENT)

    def test_identity_then_broker_relates_the_published_part_to_the_connector(self, graph):
        zpa = self._broker(graph)
        out = zpa.apply(_region(dst="198.51.100.10", port="1-1024"))
        brokered = [(reg, e) for reg, e in out if e.kind == "broker"]
        denied = [(reg, e) for reg, e in out if e.kind == "deny"]
        assert len(brokered) == 1 and len(denied) == 1
        rect = brokered[0][0].rects[0]
        assert rect.src == tuple(_intervals(["10.0.0.7"]))
        assert rect.dst == tuple(_intervals(["10.0.20.5"]))
        assert rect.dport == _ivals("443")
        assert rect.sport is None
        assert rect.request.src == tuple(_intervals(["10.0.0.5"]))
        assert brokered[0][1].data["connector"]["uid"] == "conn:1"
        assert denied[0][0].rects[0].dport == ((_PORT_FAMILY, 1, 442), (_PORT_FAMILY, 444, 1024))
        assert denied[0][1].terminal

    def test_a_denying_rule_is_terminal(self, graph):
        zpa = self._broker(graph)
        graph.access_rules[(self.IDENTITY, self.SEGMENT)][0]["action"] = "DENY"
        out = zpa.apply(_region(dst="198.51.100.10", port="443"))
        assert [(e.kind, e.terminal) for _r, e in out] == [("deny", True)]
