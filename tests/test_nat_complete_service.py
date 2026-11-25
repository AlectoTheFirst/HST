"""Strict NAT evaluates the complete tuple without asserting opaque rewrites."""

from hst.path.addrsets import _intervals, _ports
from hst.path.gates import nat
from hst.path.gates.nat import NatTransition, _nat_stage_rules
from hst.path.state import FlowRegion

TCP = frozenset({6})


def _region(*, src="10.0.0.1", dst="198.51.100.10", dport="443", sport="1000-1001"):
    return FlowRegion.from_query(
        _intervals([src]),
        _intervals([dst]),
        TCP,
        _ports(dport),
        _ports(sport),
    )


def _rule(uid, xlate, *, src_port=None, opaque=False):
    return {
        "uid": uid,
        "match_src": [],
        "match_dst": [],
        "rewrite": "src",
        "xlate": _intervals([xlate]),
        "exclude": False,
        "protos": ["tcp"],
        "port_spec": "443",
        "src_port_spec": src_port,
        "orig_src_port": src_port,
        "xlate_src_port_spec": None,
        "opaque": opaque,
        "opaque_without_src_port": opaque,
    }


def test_complete_service_source_port_scope_preserves_first_match_remainder():
    first = _rule("nat:first", "192.0.2.1", src_port="1000")
    second = _rule("nat:second", "192.0.2.2")

    out = NatTransition([first, second], complete_service=True).apply(_region())
    rewrites = [(region.rects[0], effect) for region, effect in out if effect.kind == "rewrite"]

    assert len(rewrites) == 2
    by_sport = {rect.request.sport: rect for rect, _effect in rewrites}
    assert by_sport[tuple(_ports("1000"))].src == tuple(_intervals(["192.0.2.1"]))
    assert by_sport[tuple(_ports("1001"))].src == tuple(_intervals(["192.0.2.2"]))
    assert all(rect.request.dport == tuple(_ports("443")) for rect, _effect in rewrites)


def test_complete_service_opaque_rule_does_not_claim_a_resolved_rewrite():
    rule = _rule("nat:opaque", "192.0.2.1", opaque=True)
    out = NatTransition([rule], complete_service=True).apply(_region())

    assert len(out) == 1
    rect, effect = out[0][0].rects[0], out[0][1]
    assert effect.kind == "indeterminate"
    assert rect.src == tuple(_intervals(["10.0.0.1"]))
    assert rect.request is rect


def test_complete_service_direct_opaque_rule_needs_no_loader_marker():
    rule = _rule("nat:opaque-direct", "192.0.2.1", opaque=True)
    rule.pop("opaque_without_src_port")
    out = NatTransition([rule], complete_service=True).apply(_region())

    assert out[0][1].kind == "indeterminate"
    assert out[0][0].rects[0].src == tuple(_intervals(["10.0.0.1"]))


def test_complete_service_missing_source_port_is_unknown_and_not_rewritten():
    rule = _rule("nat:sport", "192.0.2.1", src_port="1000")
    region = FlowRegion.from_query(
        _intervals(["10.0.0.1"]),
        _intervals(["198.51.100.10"]),
        TCP,
        _ports("443"),
        None,
    )
    out = NatTransition([rule], complete_service=True).apply(region)

    assert len(out) == 1
    assert out[0][1].kind == "indeterminate"
    assert out[0][1].unknown == frozenset({"sport"})
    assert out[0][0].rects[0].src == tuple(_intervals(["10.0.0.1"]))


def test_complete_service_missing_destination_port_does_not_pass_a_scoped_predicate():
    rule = _rule("nat:dport", "192.0.2.1")
    region = FlowRegion.from_query(
        _intervals(["10.0.0.1"]),
        _intervals(["198.51.100.10"]),
        TCP,
        None,
        _ports("1000"),
    )
    out = NatTransition([rule], complete_service=True).apply(region)

    assert len(out) == 1
    assert out[0][1].kind == "indeterminate"
    assert out[0][1].unknown == frozenset({"dport"})
    assert out[0][0].rects[0].src == tuple(_intervals(["10.0.0.1"]))


def test_complete_service_static_offsets_publish_explicit_address_and_port_maps():
    rule = {
        **_rule("nat:static", "192.0.2.0/24"),
        "match_src": _intervals(["10.0.0.0/24"]),
        "src_port_spec": "1000-1009",
        "orig_src_port": "1000-1009",
        "xlate_src_port_spec": "2000-2009",
    }
    out = NatTransition([rule], complete_service=True).apply(_region(src="10.0.0.8", sport="1003-1004"))

    rect, effect = out[0][0].rects[0], out[0][1]
    assert rect.src == tuple(_intervals(["192.0.2.8"]))
    assert rect.sport == tuple(_ports("2003-2004"))
    assert rect.dport == tuple(_ports("443"))
    assert set(effect.data["mappings"]) == {"src", "sport"}
    assert effect.data["mappings"]["src"]["before"] == tuple(_intervals(["10.0.0.8"]))
    assert effect.data["mappings"]["sport"]["after"] == tuple(_ports("2003-2004"))


def test_complete_service_constant_pat_defines_output_for_unstated_source_port():
    rule = {
        **_rule("nat:pat", "192.0.2.1"),
        "src_port_spec": None,
        "xlate_src_port_spec": "2000",
    }
    region = FlowRegion.from_query(
        _intervals(["10.0.0.1"]),
        _intervals(["198.51.100.10"]),
        TCP,
        _ports("443"),
        None,
    )
    out = NatTransition([rule], complete_service=True).apply(region)

    rect, effect = out[0][0].rects[0], out[0][1]
    assert effect.kind == "rewrite"
    assert rect.sport == tuple(_ports("2000"))
    assert rect.request.sport is None
    assert effect.data["mappings"]["sport"] == {
        "before": None,
        "after": tuple(_ports("2000")),
    }


def test_complete_service_constant_dnat_defines_output_for_unstated_destination_port():
    rule = {
        **_rule("nat:dnat", "10.0.0.10"),
        "rewrite": "dst",
        "port_spec": None,
        "xlate_port": 8443,
        "xlate_port_spec": "8443",
    }
    region = FlowRegion.from_query(
        _intervals(["10.0.0.1"]),
        _intervals(["198.51.100.10"]),
        TCP,
        None,
        _ports("1000"),
    )
    out = NatTransition([rule], complete_service=True).apply(region)

    rect, effect = out[0][0].rects[0], out[0][1]
    assert effect.kind == "rewrite"
    assert rect.dport == tuple(_ports("8443"))
    assert rect.request.dport is None
    assert effect.data["mappings"]["dport"]["before"] is None


def test_complete_service_unstated_source_port_to_pool_is_indeterminate():
    rule = {
        **_rule("nat:pat-pool", "192.0.2.1"),
        "src_port_spec": None,
        "xlate_src_port_spec": "2000-2009",
    }
    region = FlowRegion.from_query(
        _intervals(["10.0.0.1"]),
        _intervals(["198.51.100.10"]),
        TCP,
        _ports("443"),
        None,
    )
    out = NatTransition([rule], complete_service=True).apply(region)

    assert out[0][1].kind == "indeterminate"
    assert "source-port pool" in out[0][1].reason
    assert out[0][0].rects[0].sport is None


def test_snat_loader_keeps_source_port_specs_without_reusing_translation_as_dport():
    row = {
        "uid": "nat:snat",
        "rb_uid": "rb:nat",
        "rb_name": "NAT",
        "pos": 1,
        "kind": "snat",
        "enabled": True,
        "exclude": False,
        "protocol": "tcp",
        "orig_src_raw": "10.0.0.1",
        "orig_dst_raw": None,
        "orig_src_addrs": [],
        "orig_dst_addrs": [],
        "xlate_src_addrs": ["192.0.2.1"],
        "xlate_dst_addrs": [],
        "orig_src_port": "1000",
        "orig_dst_port": "443",
        "translation_port": "2000",
        "xlate_port": None,
        "rule_approximate": False,
        "approximate": False,
        "auto_generated": False,
        "static_flag": False,
    }
    rule = _nat_stage_rules([row], "snat", None)[0]

    assert rule["port_spec"] == "443"
    assert rule["src_port_spec"] == "1000"
    assert rule["xlate_src_port_spec"] == "2000"
    assert rule["xlate_port"] is None


def test_nat_query_reads_direct_and_redundancy_group_bindings_at_exact_snapshot():
    query = nat._NAT_RULES_QUERY_STRICT
    assert "(d:Device {uid: $dev})-[e:ENFORCES]->(rb:FwRulebase {kind: 'nat'})" in query
    assert "-[m:MEMBER_OF]->(rg:RedundancyGroup)" in query
    assert "-[e:ENFORCES]->(rb:FwRulebase {kind: 'nat'})" in query
    assert "d.collection_ts = $snap" in query
    assert "rg.collection_ts = $snap" in query
    assert "rb.collection_ts = $snap" in query
    assert "n.collection_ts = $snap" in query


def test_nat_rulebase_credits_keep_empty_rulebases_and_rule_uids(monkeypatch):
    expected = [
        {"rb_uid": "rb:empty", "rule_uids": []},
        {"rb_uid": "rb:cluster", "rule_uids": ["nat:1", "nat:2"]},
    ]

    def read(_session, query, **params):
        assert query == nat._NAT_CREDITS_QUERY
        assert params == {"dev": "dev:member", "in_if": None}
        return expected

    monkeypatch.setattr(nat._path, "_read", read)
    assert nat.nat_rulebase_credits(None, "dev:member") == expected


def test_strict_nat_does_not_drop_unmodeled_collector_metadata():
    row = {
        "uid": "nat:acl",
        "rb_uid": "rb:nat",
        "rb_name": "NAT",
        "pos": 1,
        "kind": "snat",
        "enabled": True,
        "exclude": False,
        "protocol": "tcp",
        "orig_src_raw": "10.0.0.1",
        "orig_dst_raw": None,
        "orig_src_addrs": [],
        "orig_dst_addrs": [],
        "xlate_src_addrs": ["192.0.2.1"],
        "xlate_dst_addrs": [],
        "match_route_map": "NAT-SOURCES",
        "rule_approximate": False,
        "approximate": False,
        "auto_generated": False,
        "static_flag": False,
    }
    rule = _nat_stage_rules([row], "snat", None)[0]
    out = NatTransition([rule], complete_service=True).apply(_region())

    assert rule["strict_opaque"]
    assert out[0][1].kind == "indeterminate"
    assert "route-map match" in out[0][1].reason
    assert out[0][0].rects[0].src == tuple(_intervals(["10.0.0.1"]))
