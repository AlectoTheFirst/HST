from types import SimpleNamespace

import pytest

from hst import path
from hst.core.config import Settings
from hst.path import DENY, INDETERMINATE, PERMIT, classify_action
from hst.path.addrsets import (
    _MATCH,
    _NO_MATCH,
    _UNKNOWN,
    _combine_and,
    _combine_or,
    _intersect,
    _merge,
    _port_matches,
    _ports,
    _proto_matches,
    _protoset,
)
from hst.path.gates import firewall, pbr
from hst.path.gates.firewall import (
    _as_portset,
    _as_protoset,
    _first_match,
    _first_match_point,
    _first_match_regions,
)


class TestClassifyAction:
    @pytest.mark.parametrize("action", ["accept", "permit", "allow", "ACCEPT", " Allow "])
    def test_permit_words(self, action):
        assert classify_action(action) == PERMIT

    @pytest.mark.parametrize("action", ["drop", "reject", "deny", "Blocked", "BLOCK"])
    def test_deny_words(self, action):
        assert classify_action(action) == DENY

    @pytest.mark.parametrize("action", ["", None, "inline-layer", "d29a1b0e-uid", "userauth"])
    def test_anything_unrecognised_is_indeterminate_not_permitted(self, action):
        assert classify_action(action) == INDETERMINATE


# --- Check Point: rulebase bound to the device, no zones anywhere -----------------------

RB = {
    "rb_uid": "cp:rb1",
    "rb_name": "Standard",
    "vendor": "checkpoint",
    # the layer's implicit cleanup action, as the collector records it
    "default_action": "drop",
    "approximate": False,
}


def _rule(**kw):
    base = {
        "uid": "cp:r1",
        "pos": 1,
        "action": "accept",
        "name": "web",
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


@pytest.fixture()
def graph(monkeypatch):
    """Drives the two read seams from a per-test script."""
    state = {"rb": RB, "rules": [], "names": []}

    def fake_read_one(session, query, **params):
        return None

    def fake_read(session, query, **params):
        if "ENFORCES" in query:
            return [state["rb"]] if state["rb"] else []
        if "i.uid IN" in query:
            return state["names"]
        if "HAS_RULE" in query:
            return state["rules"]
        return []

    monkeypatch.setattr(path, "_read_one", fake_read_one)
    monkeypatch.setattr(path, "_read", fake_read)
    return state


def _verdict(src="10.0.0.0/24", dst="10.9.9.0/24", port=443, proto="tcp"):
    return path._device_rulebase_verdict(
        None, "dev:fw1", "if:in", "if:out", path._intervals([src]), path._intervals([dst]), port, proto, 4
    )


def test_no_rulebase_on_the_device_returns_none(graph):
    graph["rb"] = None
    assert _verdict() is None


def test_an_any_any_accept_permits(graph):
    graph["rules"] = [_rule(src_any=True, dst_any=True, svc_any=True)]
    v = _verdict()
    assert classify_action(v["action"]) == PERMIT
    assert v["rule_uid"] == "cp:r1"


def test_a_matching_drop_blocks(graph):
    graph["rules"] = [_rule(action="drop", src_any=True, dst_any=True, svc_any=True)]
    assert classify_action(_verdict()["action"]) == DENY


def test_first_match_wins_by_position(graph):
    graph["rules"] = [
        _rule(uid="cp:r1", pos=1, action="drop", src_any=True, dst_any=True, svc_any=True),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "cp:r1" and classify_action(v["action"]) == DENY


def test_no_rule_matches_falls_to_an_implicit_drop(graph):
    graph["rules"] = [_rule(src_cidrs=["192.168.0.0/24"], dst_any=True, svc_any=True)]
    v = _verdict()
    assert classify_action(v["action"]) == DENY
    assert v["by"] == "default-action"


def test_a_rulebase_stating_no_default_and_no_marker_is_undecided_not_a_drop(graph, caplog):
    graph["rb"] = {**RB, "rb_uid": "cp:unstated", "default_action": None}
    graph["rules"] = [_rule(src_cidrs=["192.168.0.0/24"], dst_any=True, svc_any=True)]
    with caplog.at_level("WARNING", logger="hst.path.gates.firewall"):
        v = _verdict()
    assert v["by"] == "default-action"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == _UNSTATED_DEFAULT
    assert any("rulebase cp:unstated" in r.getMessage() for r in caplog.records)


def test_a_rule_with_neither_objects_nor_any_is_undecided_not_skipped(graph):
    graph["rules"] = [
        _rule(uid="cp:r1", pos=1, action="drop"),  # no objects, no any
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE
    assert firewall._EMPTY_SIDE_REASON in v["indeterminate_reason"]


def test_a_deny_rule_whose_addresses_do_not_parse_is_indeterminate_not_skipped(graph):
    graph["rules"] = [
        _rule(uid="cp:r1", pos=1, action="drop", src_cidrs=["not-an-address"], dst_any=True, svc_any=True),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE


def test_a_resolved_object_based_rule_matches(graph):
    graph["rules"] = [
        _rule(src_cidrs=["10.0.0.0/24"], src_obj_count=1, src_opaque=False, dst_any=True, svc_any=True)
    ]
    assert classify_action(_verdict()["action"]) == PERMIT


def test_a_group_rule_matches_through_its_closure(graph):
    """A group's RESOLVES_TO closure (checkpoint.py, collector-side) lands the
    group's members' addresses on the same one-hop edge a bare object uses; the
    gate does not need to know the source object was a group."""
    graph["rules"] = [
        _rule(src_cidrs=["10.1.1.10/32"], src_obj_count=1, src_opaque=False, dst_any=True, svc_any=True)
    ]
    v = _verdict(src="10.1.1.10")
    assert classify_action(v["action"]) == PERMIT


def test_a_known_member_match_wins_over_opacity(graph):
    graph["rules"] = [
        _rule(src_cidrs=["10.0.0.0/24"], src_obj_count=1, src_opaque=True, dst_any=True, svc_any=True)
    ]
    assert classify_action(_verdict()["action"]) == PERMIT


def test_a_non_matching_opaque_side_is_indeterminate_not_skipped(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1", pos=1, action="drop", src_obj_count=1, src_opaque=True, dst_any=True, svc_any=True
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE


def test_referenced_objects_with_no_address_are_indeterminate(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1", pos=1, action="drop", src_obj_count=1, src_opaque=False, dst_any=True, svc_any=True
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE


def test_a_service_group_expands_to_its_members_proto_and_port(graph):
    graph["rules"] = [_rule(src_any=True, dst_any=True, protos=["tcp", "udp"], ports=["80", "53"])]
    v = _verdict(port=53, proto="udp")
    assert classify_action(v["action"]) == PERMIT


def test_a_service_other_member_makes_a_non_match_indeterminate(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            protos=["tcp"],
            ports=["80"],
            svc_opaque=True,
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(port=443, proto="udp")
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE


def test_negated_source_matches_the_complement(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_cidrs=["10.0.0.0/24"],
            src_obj_count=1,
            src_negate=True,
            dst_any=True,
            svc_any=True,
        )
    ]
    inside = _verdict(src="10.0.0.5")
    assert inside["by"] == "default-action"  # r1 did not match; falls through
    outside = _verdict(src="192.168.1.5")
    assert outside["rule_uid"] == "cp:r1" and classify_action(outside["action"]) == DENY


def test_negated_opaque_source_is_indeterminate(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_obj_count=1,
            src_opaque=True,
            src_negate=True,
            dst_any=True,
            svc_any=True,
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE


def test_negated_any_source_matches_no_flow(graph):
    graph["rules"] = [
        _rule(uid="cp:r1", pos=1, action="drop", src_any=True, src_negate=True, dst_any=True, svc_any=True),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "cp:r2"
    assert classify_action(v["action"]) == PERMIT


def test_svc_negate_inverts_the_proto_port_predicate(graph):
    """svc_negate=True on a rule scoped to tcp does not match a tcp
    flow of the same addresses, but does match a udp flow."""
    graph["rules"] = [_rule(src_any=True, dst_any=True, protos=["tcp"], svc_negate=True)]
    assert _verdict(proto="tcp")["by"] == "default-action"  # svc side excludes tcp
    v = _verdict(proto="udp")
    assert classify_action(v["action"]) == PERMIT


def test_negated_any_service_matches_no_flow(graph):
    graph["rules"] = [
        _rule(uid="cp:r1", pos=1, action="drop", src_any=True, dst_any=True, svc_any=True, svc_negate=True),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "cp:r2"
    assert classify_action(v["action"]) == PERMIT


def test_a_negated_service_side_whose_known_members_match_is_a_confident_non_match(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            protos=["tcp"],
            ports=["443"],
            svc_obj_count=2,
            svc_opaque=True,
            svc_negate=True,
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(port=443, proto="tcp")
    assert v["rule_uid"] == "cp:r2" and classify_action(v["action"]) == PERMIT


def test_a_negated_opaque_service_side_that_does_not_match_is_indeterminate(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            protos=["tcp"],
            ports=["443"],
            svc_obj_count=2,
            svc_opaque=True,
            svc_negate=True,
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(port=22, proto="tcp")
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE


def test_a_lone_service_other_object_does_not_match_every_flow(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            svc_obj_count=1,
            svc_opaque=True,
            svc_opaque_reasons=["unsupported checkpoint service kind: service-other"],
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE


def test_a_service_group_of_only_opaque_members_does_not_match_every_flow(graph):
    """The same shape one level up: the group is one SVC object whose whole
    membership resolved to nothing the engine can compare a flow against."""
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            svc_obj_count=1,
            svc_opaque=True,
            svc_opaque_reasons=[
                "unsupported checkpoint service kind: service-other",
                "unsupported checkpoint service kind: service-dce-rpc",
            ],
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE


def test_services_that_carry_no_protocol_or_port_name_that_as_the_reason(graph):
    graph["rules"] = [
        _rule(uid="cp:r1", pos=1, action="drop", src_any=True, dst_any=True, svc_obj_count=1),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == "referenced services carry no protocol or port"


def test_a_rule_with_no_service_objects_matches_on_its_addresses(graph):
    graph["rules"] = [_rule(src_any=True, dst_any=True, svc_obj_count=0)]
    assert classify_action(_verdict()["action"]) == PERMIT


def test_a_negated_source_covers_the_flows_own_address_family(graph):
    graph["rules"] = [
        _rule(
            src_cidrs=["10.0.0.0/24"],
            src_obj_count=1,
            src_negate=True,
            dst_any=True,
            svc_any=True,
        )
    ]
    v = path._device_rulebase_verdict(
        None,
        "dev:fw1",
        "if:in",
        "if:out",
        path._intervals(["2001:db8::1"]),
        path._intervals(["2001:db8:9::1"]),
        443,
        "tcp",
        6,
    )
    assert v["rule_uid"] == "cp:r1" and classify_action(v["action"]) == PERMIT


def test_a_negated_opaque_source_that_excludes_the_whole_flow_is_a_confident_non_match(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_cidrs=["10.0.0.0/24"],
            src_obj_count=2,
            src_opaque=True,
            src_negate=True,
            dst_any=True,
            svc_any=True,
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "cp:r2" and classify_action(v["action"]) == PERMIT


def test_a_negated_opaque_source_that_excludes_only_part_of_the_flow_is_indeterminate(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_cidrs=["10.0.0.128/25"],
            src_obj_count=2,
            src_opaque=True,
            src_negate=True,
            src_opaque_reasons=["an access-role identifies users, not addresses"],
            dst_any=True,
            svc_any=True,
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE


def _leg_note(graph, rule_row, port=443, proto="tcp"):
    """The warning `_apply_firewall` writes for one rule, over the fake graph."""
    from hst.path.gates.firewall import _apply_firewall

    graph["rules"] = [rule_row]
    trail, leg = path._Trail(), {}
    _apply_firewall(
        None,
        trail,
        leg,
        {"dev_uid": "dev:fw1", "if_uid": "if:in"},
        "if:out",
        path._intervals(["10.0.0.0/24"]),
        path._intervals(["10.9.9.0/24"]),
        port,
        proto,
        "10.0.0.0/24",
        "eth0",
    )
    assert leg["indeterminate"] is True
    return " ".join(trail.warnings)


def test_the_leg_note_names_the_opaque_reason_not_the_action(graph):
    note = _leg_note(
        graph,
        _rule(
            action="drop",
            src_obj_count=1,
            src_opaque=True,
            src_opaque_reasons=["an access-role identifies users, not addresses"],
            dst_any=True,
            svc_any=True,
        ),
    )
    assert "an access-role identifies users, not addresses" in note
    assert "does not evaluate" not in note


def test_the_leg_note_says_when_a_side_carries_no_address(graph):
    note = _leg_note(graph, _rule(action="drop", src_obj_count=1, dst_any=True, svc_any=True))
    assert "referenced objects carry no address" in note
    assert "does not evaluate" not in note


def test_the_leg_note_says_when_addresses_could_not_be_parsed(graph):
    note = _leg_note(graph, _rule(action="drop", src_cidrs=["not-an-address"], dst_any=True, svc_any=True))
    assert "the addresses this rule lists could not be parsed" in note
    assert "does not evaluate" not in note


def test_unparsed_addresses_do_not_trip_when_the_service_excludes_the_flow(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_cidrs=["not-an-address"],
            dst_any=True,
            protos=["tcp"],
            ports=["22"],
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(port=443)
    assert v["rule_uid"] == "cp:r2"
    assert classify_action(v["action"]) == PERMIT


def test_the_candidates_query_recognizes_the_redundancygroup_binding():
    from hst.path.gates.firewall import _RULEBASE_CANDIDATES

    assert "MEMBER_OF]->(:RedundancyGroup)-[e3:ENFORCES]->(rb:FwRulebase:Obj)" in _RULEBASE_CANDIDATES
    assert _RULEBASE_CANDIDATES.count("rb.collection_ts = $snap") == 3
    assert _RULEBASE_CANDIDATES.count("FROM_ZONE|TO_ZONE") == 3


def test_the_vendor_query_recognizes_the_redundancygroup_binding():
    from hst.path.gates.firewall import _ACCESS_VENDOR_QUERY

    assert "MEMBER_OF]->(:RedundancyGroup)-[e3:ENFORCES]->(rb2:FwRulebase)" in _ACCESS_VENDOR_QUERY


def test_a_redundancygroup_bound_rulebase_is_evaluated_to_a_real_verdict(monkeypatch):
    rb_row = {
        "rb_uid": "cp:rg1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "af": None,
        "default_action": None,
        "default_action_unknown": None,
        "global_state_policy": None,
        "match_context": None,
        "chain": None,
        "approximate": False,
    }

    def fake_read(session, query, **params):
        if "MEMBER_OF]->(:RedundancyGroup)-[e3:ENFORCES]->(rb:FwRulebase:Obj)" in query:
            return [rb_row]
        if "HAS_RULE" in query:
            return [_rule(action="drop", src_any=True, dst_any=True, svc_any=True)]
        return []

    monkeypatch.setattr(path, "_read", fake_read)
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    v = _verdict()
    assert classify_action(v["action"]) == DENY
    assert v["rule_uid"] == "cp:r1"


def test_zone_bound_rulebases_are_excluded_from_the_device_fallback(monkeypatch):
    queries = []

    def fake_read(session, query, **params):
        queries.append((query, params))
        return []

    monkeypatch.setattr(path, "_read", fake_read)
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    assert _verdict() is None
    enforcing, params = next((q, p) for q, p in queries if "ENFORCES" in q)
    assert "FROM_ZONE|TO_ZONE" in enforcing and "NOT EXISTS" in enforcing
    assert "coalesce(rb.chain, 'forward') = $chain" in enforcing
    assert params["chain"] == "forward"


# --- crediting the zone pairs a flow does not cross ------------------------------------


def _zone_rb(rb_uid, src_zone, dst_zone, af=4, dst_unbound=False):
    return {
        "rb_uid": rb_uid,
        "af": af,
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "dst_unbound": dst_unbound,
    }


def test_other_zone_pair_rulebases_credits_the_pairs_a_flow_does_not_cross(monkeypatch):
    rows = [
        _zone_rb("rb:lan-wan", "LAN", "WAN"),
        _zone_rb("rb:guest-wan", "GUEST", "WAN"),
        _zone_rb("rb:iot-lan", "IOT", "LAN"),
    ]
    monkeypatch.setattr(path, "_read", lambda s, q, **p: rows)
    credited = firewall._other_zone_pair_rulebases(None, "dev:r1", ("LAN", "WAN"), 4)
    assert sorted(credited) == ["rb:guest-wan", "rb:iot-lan"]


def test_other_zone_pair_rulebases_credits_the_ipv6_ruleset_for_a_v4_flow(monkeypatch):
    """The same pair bound for the other address family is a checkable
    exclusion too: a v4 flow never crosses the v6 ruleset for LAN->WAN."""
    rows = [
        _zone_rb("rb:lan-wan-v4", "LAN", "WAN", af=4),
        _zone_rb("rb:lan-wan-v6", "LAN", "WAN", af=6),
    ]
    monkeypatch.setattr(path, "_read", lambda s, q, **p: rows)
    credited = firewall._other_zone_pair_rulebases(None, "dev:r1", ("LAN", "WAN"), 4)
    assert credited == ["rb:lan-wan-v6"]


def test_other_zone_pair_rulebases_does_not_credit_a_pair_that_matches_but_was_not_read(monkeypatch):
    rows = [_zone_rb("rb:lan-wan", "LAN", "WAN", af=4)]
    monkeypatch.setattr(path, "_read", lambda s, q, **p: rows)
    assert firewall._other_zone_pair_rulebases(None, "dev:r1", ("LAN", "WAN"), 4) == []


def test_other_zone_pair_rulebases_returns_nothing_without_a_resolved_pair(monkeypatch):
    """No ingress/egress zone pair was read at all (an unzoned interface, or
    both sides in the same zone): nothing is a checkable exclusion."""
    monkeypatch.setattr(path, "_read", lambda s, q, **p: (_ for _ in ()).throw(AssertionError("no read")))
    assert firewall._other_zone_pair_rulebases(None, "dev:r1", None, 4) == []


def test_local_zone_name_finds_an_unambiguous_unbound_zone(monkeypatch):
    """A TO_ZONE target with no CONTAINS edge to any interface is the
    structural signature of a zone standing for the router itself."""
    rows = [
        _zone_rb("rb:lan-wan", "LAN", "WAN"),
        _zone_rb("rb:lan-local", "LAN", "LOCAL", dst_unbound=True),
    ]
    monkeypatch.setattr(path, "_read", lambda s, q, **p: rows)
    assert firewall._local_zone_name(None, "dev:r1", "LAN") == "LOCAL"


def test_local_zone_name_is_none_when_the_zone_model_records_none(monkeypatch):
    rows = [_zone_rb("rb:lan-wan", "LAN", "WAN"), _zone_rb("rb:guest-wan", "GUEST", "WAN")]
    monkeypatch.setattr(path, "_read", lambda s, q, **p: rows)
    assert firewall._local_zone_name(None, "dev:r1", "LAN") is None


def test_local_zone_name_is_none_when_more_than_one_unbound_zone_is_ambiguous(monkeypatch):
    rows = [
        _zone_rb("rb:lan-local", "LAN", "LOCAL", dst_unbound=True),
        _zone_rb("rb:lan-dmz", "LAN", "DMZ", dst_unbound=True),
    ]
    monkeypatch.setattr(path, "_read", lambda s, q, **p: rows)
    assert firewall._local_zone_name(None, "dev:r1", "LAN") is None


# --- crediting a PbrPolicy bound to another interface -----------------------------------


def test_other_interface_pbr_policies_credits_the_other_interface(monkeypatch):
    rows = [
        {"pol_uid": "pbr:wg-main", "if_uid": "if:wg0"},
        {"pol_uid": "pbr:wg-dedicated", "if_uid": "if:wg1"},
    ]
    monkeypatch.setattr(path, "_read", lambda s, q, **p: rows)
    credited = pbr._other_interface_pbr_policies(None, "dev:r1", "if:eth0")
    assert sorted(credited) == ["pbr:wg-dedicated", "pbr:wg-main"]


def test_other_interface_pbr_policies_leaves_the_ingress_interface_alone(monkeypatch):
    rows = [{"pol_uid": "pbr:ingress", "if_uid": "if:eth0"}, {"pol_uid": "pbr:wg-main", "if_uid": "if:wg0"}]
    monkeypatch.setattr(path, "_read", lambda s, q, **p: rows)
    assert pbr._other_interface_pbr_policies(None, "dev:r1", "if:eth0") == ["pbr:wg-main"]


def test_port_scoping_is_honoured(graph):
    graph["rules"] = [
        _rule(uid="cp:r1", pos=1, action="accept", src_any=True, dst_any=True, protos=["tcp"], ports=["80"]),
        _rule(uid="cp:r2", pos=2, action="drop", src_any=True, dst_any=True, svc_any=True),
    ]
    assert _verdict(port=443)["rule_uid"] == "cp:r2"
    assert _verdict(port=80)["rule_uid"] == "cp:r1"


def test_device_rulebases_pick_the_flows_address_family(monkeypatch):
    v4 = {**RB, "rb_uid": "vyos:gw:fw:ipv4-forward", "rb_name": "ipv4-forward", "af": 4}
    v6 = {
        **RB,
        "rb_uid": "vyos:gw:fw:ipv6-forward",
        "rb_name": "ipv6-forward",
        "af": 6,
        "default_action": "drop",
    }
    state = {"rules": [_rule(src_any=True, dst_any=True, svc_any=True)]}
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(
        path,
        "_read",
        lambda s, q, **p: [v4, v6] if "ENFORCES" in q else (state["rules"] if "HAS_RULE" in q else []),
    )
    v = path._device_rulebase_verdict(
        None,
        "dev:gw",
        "if:in",
        "if:out",
        path._intervals(["10.0.0.5"]),
        path._intervals(["8.8.8.8"]),
        443,
        "tcp",
        4,
    )
    assert v["rb_name"] == "ipv4-forward" and classify_action(v["action"]) == PERMIT


def test_rulebases_without_af_fall_back_to_the_uid_convention(monkeypatch):
    legacy_v6 = {
        **RB,
        "rb_uid": "vyos:gw:fw:ipv6-forward",
        "rb_name": "ipv6-forward",
        "default_action": "drop",
    }
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", lambda s, q, **p: [legacy_v6] if "ENFORCES" in q else [])
    v = path._device_rulebase_verdict(
        None,
        "dev:gw",
        "if:in",
        "if:out",
        path._intervals(["10.0.0.5"]),
        path._intervals(["8.8.8.8"]),
        443,
        "tcp",
        4,
    )
    assert v is None


def test_a_flow_must_pass_every_device_rulebase(monkeypatch):
    permit_rb = {**RB, "rb_uid": "cp:rb1", "rb_name": "A-permits"}
    deny_rb = {**RB, "rb_uid": "cp:rb2", "rb_name": "B-denies"}
    rules = {
        "cp:rb1": [_rule(src_any=True, dst_any=True, svc_any=True)],
        "cp:rb2": [_rule(uid="cp:r9", action="drop", src_any=True, dst_any=True, svc_any=True)],
    }
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(
        path,
        "_read",
        lambda s, q, **p: [permit_rb, deny_rb] if "ENFORCES" in q else (rules.get(p.get("rb"), [])),
    )
    v = path._device_rulebase_verdict(
        None,
        "dev:fw1",
        "if:in",
        "if:out",
        path._intervals(["10.0.0.5"]),
        path._intervals(["8.8.8.8"]),
        443,
        "tcp",
        4,
    )
    assert v["rb_name"] == "B-denies" and classify_action(v["action"]) == DENY


# --- Cisco interface ACLs: match_context='interface-acl' candidacy and scoping ----------

_ACL_RB = {**RB, "vendor": "cisco", "match_context": "interface-acl", "default_action": "deny"}


def _bound(*pairs: tuple[str, str]) -> list[list[str]]:
    """The `acl_bindings` column of a candidate row: one [name, direction] pair per
    PROTECTED_BY edge, the bound interface's name and the edge's direction."""
    return [[name, direction] for name, direction in pairs]


def _acl_read(monkeypatch, rulebases: list[dict], rules: dict[str, list[dict]], names: dict[str, str]):
    name_rows = [{"uid": u, "name": n} for u, n in names.items()]
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(
        path,
        "_read",
        lambda s, q, **p: (
            rulebases if "ENFORCES" in q else name_rows if "i.uid IN" in q else rules.get(p.get("rb"), [])
        ),
    )


def _acl_verdict(in_if="if:in", out_if="if:out"):
    return path._device_rulebase_verdict(
        None,
        "dev:fw1",
        in_if,
        out_if,
        path._intervals(["10.0.0.5"]),
        path._intervals(["8.8.8.8"]),
        443,
        "tcp",
        4,
    )


def test_a_single_applicable_interface_acl_that_denies_blocks(monkeypatch):
    """Mirrors test_a_matching_drop_blocks for the Cisco match_context: an ACL
    bound to this hop's ingress interface, with a deny rule, blocks the flow."""
    rb = {**_ACL_RB, "rb_uid": "cisco:edge-in", "rb_name": "EDGE-IN", "acl_bindings": _bound(("Gi0/1", "in"))}
    rules = {"cisco:edge-in": [_rule(action="deny", src_any=True, dst_any=True, svc_any=True)]}
    _acl_read(monkeypatch, [rb], rules, {"if:in": "Gi0/1"})
    v = _acl_verdict()
    assert v["rb_uid"] == "cisco:edge-in"
    assert classify_action(v["action"]) == DENY


def test_an_acl_bound_to_another_interface_is_excluded_not_defaulted_to_deny(monkeypatch):
    unrelated = {
        **_ACL_RB,
        "rb_uid": "cisco:mgmt-out",
        "rb_name": "MGMT-OUT",
        "acl_bindings": _bound(("Mgmt0", "out")),
    }
    applicable = {
        **_ACL_RB,
        "rb_uid": "cisco:edge-in",
        "rb_name": "EDGE-IN",
        "acl_bindings": _bound(("Gi0/1", "in")),
    }
    rules = {
        "cisco:mgmt-out": [
            _rule(
                uid="cisco:mgmt-out:1",
                action="deny",
                src_any=True,
                dst_any=True,
                svc_any=True,
            )
        ],
        "cisco:edge-in": [
            _rule(
                uid="cisco:edge-in:1",
                action="permit",
                src_any=True,
                dst_any=True,
                svc_any=True,
            )
        ],
    }
    _acl_read(monkeypatch, [unrelated, applicable], rules, {"if:in": "Gi0/1", "if:out": "Gi0/2"})
    v = _acl_verdict()
    assert v["rb_uid"] == "cisco:edge-in"
    assert classify_action(v["action"]) == PERMIT


def test_an_acl_bound_only_elsewhere_on_the_device_yields_no_verdict(monkeypatch):
    unrelated = {
        **_ACL_RB,
        "rb_uid": "cisco:mgmt-out",
        "rb_name": "MGMT-OUT",
        "acl_bindings": _bound(("Mgmt0", "out")),
    }
    rules = {"cisco:mgmt-out": [_rule(action="deny", src_any=True, dst_any=True, svc_any=True)]}
    _acl_read(monkeypatch, [unrelated], rules, {"if:in": "Gi0/1", "if:out": "Gi0/2"})
    assert _acl_verdict() is None


def test_an_acl_scoped_to_an_unresolved_hop_interface_is_indeterminate_not_excluded(monkeypatch):
    rb = {
        **_ACL_RB,
        "rb_uid": "cisco:mgmt-out",
        "rb_name": "MGMT-OUT",
        "acl_bindings": _bound(("Mgmt0", "out")),
    }
    rules = {"cisco:mgmt-out": [_rule(action="deny", src_any=True, dst_any=True, svc_any=True)]}
    _acl_read(monkeypatch, [rb], rules, {})  # neither interface uid resolves to a name
    v = _acl_verdict()
    assert classify_action(v["action"]) == INDETERMINATE
    assert "Mgmt0" in v["indeterminate_reason"]


def test_an_applicable_interface_acl_with_no_matching_rule_falls_to_its_implicit_deny(monkeypatch):
    rb = {**_ACL_RB, "rb_uid": "cisco:edge-in", "rb_name": "EDGE-IN", "acl_bindings": _bound(("Gi0/1", "in"))}
    rules = {"cisco:edge-in": [_rule(src_cidrs=["192.168.0.0/24"], dst_any=True, svc_any=True)]}
    _acl_read(monkeypatch, [rb], rules, {"if:in": "Gi0/1"})
    v = _acl_verdict()
    assert classify_action(v["action"]) == DENY
    assert v["by"] == "default-action"


def test_an_established_ace_is_skipped_as_a_connection_state_not_indeterminate(monkeypatch):
    from hst.path.gates.firewall import _apply_firewall

    rb = {**_ACL_RB, "rb_uid": "cisco:edge-in", "rb_name": "EDGE-IN", "acl_bindings": _bound(("Gi0/1", "in"))}
    rules = {
        "cisco:edge-in": [
            _rule(
                pos=1,
                action="permit",
                src_any=True,
                dst_any=True,
                svc_any=True,
                states=["established"],
            )
        ]
    }
    _acl_read(monkeypatch, [rb], rules, {"if:in": "Gi0/1"})
    trail, leg = path._Trail(), {}
    outcome = _apply_firewall(
        None,
        trail,
        leg,
        {"dev_uid": "dev:fw1", "if_uid": "if:in"},
        "if:out",
        path._intervals(["10.0.0.5"]),
        path._intervals(["8.8.8.8"]),
        443,
        "tcp",
        "10.0.0.5",
        "eth0",
    )
    assert outcome == DENY
    assert leg.get("indeterminate") is not True
    notes = " ".join(trail.notes)
    assert "rule 1 is scoped to connection state established" in notes
    assert "new connection" in notes


def test_an_unresolved_object_group_ace_that_otherwise_matches_is_indeterminate(monkeypatch):
    """The other opaque path an interface ACL can hit: an ACE side the
    collector could not resolve to a concrete address (an object-group) mints
    an opaque NetObject, and a rule that side would otherwise leave matching is
    indeterminate with the collector's reason, not a confident permit."""
    rb = {**_ACL_RB, "rb_uid": "cisco:edge-in", "rb_name": "EDGE-IN", "acl_bindings": _bound(("Gi0/1", "in"))}
    reason = "the ACE matches object-group 'PARTNERS', which is not collected"
    rules = {
        "cisco:edge-in": [
            _rule(
                action="permit",
                src_obj_count=1,
                src_opaque=True,
                src_opaque_reasons=[reason],
                dst_any=True,
                svc_any=True,
            )
        ]
    }
    _acl_read(monkeypatch, [rb], rules, {"if:in": "Gi0/1"})
    v = _acl_verdict()
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == reason


def test_a_qualifier_opaque_service_that_otherwise_matches_is_indeterminate(monkeypatch):
    rb = {**_ACL_RB, "rb_uid": "cisco:edge-in", "rb_name": "EDGE-IN", "acl_bindings": _bound(("Gi0/1", "in"))}
    reason = "the rule matches on the TCP flags 'syn', which the traced flow does not state"
    rules = {
        "cisco:edge-in": [
            _rule(
                action="permit",
                src_any=True,
                dst_any=True,
                svc_obj_count=1,
                svc_opaque=True,
                svc_opaque_reasons=[reason],
            )
        ]
    }
    _acl_read(monkeypatch, [rb], rules, {"if:in": "Gi0/1"})
    v = _acl_verdict()
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == reason


def test_an_af_mismatched_interface_acl_is_credited_to_considered(monkeypatch):
    rb = {
        **_ACL_RB,
        "rb_uid": "cisco:edge-in",
        "rb_name": "EDGE-IN",
        "acl_bindings": _bound(("Gi0/1", "in")),
        "af": 4,
    }
    rules = {"cisco:edge-in": [_rule(action="deny", src_any=True, dst_any=True, svc_any=True)]}
    _acl_read(monkeypatch, [rb], rules, {"if:in": "Gi0/1"})
    considered: list[str] = []
    v = path._device_rulebase_verdict(
        None,
        "dev:fw1",
        "if:in",
        "if:out",
        path._intervals(["2001:db8::1"]),
        path._intervals(["2001:db8::2"]),
        443,
        "tcp",
        6,
        considered=considered,
    )
    assert v is None
    assert considered == ["cisco:edge-in"]


def test_every_judged_device_wide_candidate_is_credited_to_considered(monkeypatch):
    permit_rb = {**RB, "rb_uid": "cp:permit", "rb_name": "permit-all"}
    deny_rb = {**RB, "rb_uid": "cp:deny", "rb_name": "deny-all"}
    rules = {
        "cp:permit": [_rule(uid="cp:permit:1", action="accept", src_any=True, dst_any=True, svc_any=True)],
        "cp:deny": [_rule(uid="cp:deny:1", action="drop", src_any=True, dst_any=True, svc_any=True)],
    }
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(
        path,
        "_read",
        lambda s, q, **p: [permit_rb, deny_rb] if "ENFORCES" in q else rules.get(p.get("rb"), []),
    )
    considered: list[str] = []
    v = path._device_rulebase_verdict(
        None,
        "dev:fw1",
        "if:in",
        "if:out",
        path._intervals(["10.0.0.5"]),
        path._intervals(["8.8.8.8"]),
        443,
        "tcp",
        4,
        considered=considered,
    )
    assert classify_action(v["action"]) == DENY
    assert considered == ["cp:permit", "cp:deny"]


def test_the_other_familys_forward_chain_is_credited_to_considered(monkeypatch):
    v4 = {**RB, "rb_uid": "vyos:gw:fw:ipv4-forward", "rb_name": "ipv4-forward", "af": 4, "chain": "forward"}
    v6 = {**RB, "rb_uid": "vyos:gw:fw:ipv6-forward", "rb_name": "ipv6-forward", "af": 6, "chain": "forward"}
    rules = {v4["rb_uid"]: [_rule(action="accept", src_any=True, dst_any=True, svc_any=True)]}
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(
        path,
        "_read",
        lambda s, q, **p: [v4, v6] if "ENFORCES" in q else rules.get(p.get("rb"), []),
    )
    considered: list[str] = []
    v = path._device_rulebase_verdict(
        None,
        "dev:gw",
        "if:in",
        "if:out",
        path._intervals(["10.0.0.5"]),
        path._intervals(["8.8.8.8"]),
        443,
        "tcp",
        4,
        considered=considered,
    )
    assert classify_action(v["action"]) == PERMIT
    assert sorted(considered) == ["vyos:gw:fw:ipv4-forward", "vyos:gw:fw:ipv6-forward"]


def test_apply_firewall_an_acl_bound_elsewhere_credits_fw_uids_with_no_outcome(monkeypatch):
    from hst.path.gates.firewall import _apply_firewall

    rb = {
        **_ACL_RB,
        "rb_uid": "cisco:mgmt-out",
        "rb_name": "MGMT-OUT",
        "acl_bindings": _bound(("Mgmt0", "out")),
    }
    rules = {"cisco:mgmt-out": [_rule(action="deny", src_any=True, dst_any=True, svc_any=True)]}
    _acl_read(monkeypatch, [rb], rules, {"if:in": "Gi0/1", "if:out": "Gi0/2"})
    trail, leg = path._Trail(), {}
    outcome = _apply_firewall(
        None,
        trail,
        leg,
        {"dev_uid": "dev:fw1", "if_uid": "if:in"},
        "if:out",
        path._intervals(["10.0.0.5"]),
        path._intervals(["8.8.8.8"]),
        443,
        "tcp",
        "10.0.0.5",
        "eth0",
    )
    assert outcome is None
    assert leg["fw_uids"] == ["cisco:mgmt-out"]
    assert "fw_uid" not in leg


def test_apply_firewall_an_applicable_denying_acl_credits_both_fw_uid_and_fw_uids(monkeypatch):
    """An ACL that does govern this hop and denies the flow puts its uid on
    both the singular `fw_uid` (the leg's decisive rulebase) and `fw_uids`
    (every rulebase this leg's gate looked at)."""
    from hst.path.gates.firewall import _apply_firewall

    rb = {**_ACL_RB, "rb_uid": "cisco:edge-in", "rb_name": "EDGE-IN", "acl_bindings": _bound(("Gi0/1", "in"))}
    rules = {"cisco:edge-in": [_rule(action="deny", src_any=True, dst_any=True, svc_any=True)]}
    _acl_read(monkeypatch, [rb], rules, {"if:in": "Gi0/1"})
    trail, leg = path._Trail(), {}
    outcome = _apply_firewall(
        None,
        trail,
        leg,
        {"dev_uid": "dev:fw1", "if_uid": "if:in"},
        "if:out",
        path._intervals(["10.0.0.5"]),
        path._intervals(["8.8.8.8"]),
        443,
        "tcp",
        "10.0.0.5",
        "eth0",
    )
    assert outcome == DENY
    assert leg["fw_uid"] == "cisco:edge-in"
    assert leg["fw_uids"] == ["cisco:edge-in"]


def test_zone_pair_picks_the_flows_address_family(monkeypatch):
    v4_row = {
        "rb_uid": "vyos:gw:fw:GUEST-WAN",
        "rb_name": "GUEST-WAN",
        "af": 4,
        "default_action": None,
        "src_zone": "GUEST",
        "dst_zone": "WAN",
        "zone_default": "drop",
    }
    v6_row = {**v4_row, "rb_uid": "vyos:gw:fw:ipv6:GUEST6-WAN6", "rb_name": "GUEST6-WAN6", "af": 6}
    rules = [_rule(src_any=True, dst_any=True, svc_any=True)]
    seen_rb = []

    def fake_read(s, q, **p):
        if "FROM_ZONE" in q:
            return [v6_row, v4_row]  # v6 first: order must not matter
        if "HAS_RULE" in q:
            seen_rb.append(p["rb"])
            return rules
        return []

    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", fake_read)
    src, dst = path._intervals(["192.168.110.53"]), path._intervals(["8.8.8.8"])
    v = path._zone_pair_verdict(None, "if:in", "if:out", src, dst, 443, "tcp", 4)
    assert v["rb_name"] == "GUEST-WAN"
    assert seen_rb == ["vyos:gw:fw:GUEST-WAN"]


def test_zone_pair_without_a_ruleset_for_the_family_drops_by_zone_default(monkeypatch):
    v6_row = {
        "rb_uid": "vyos:gw:fw:ipv6:GUEST6-WAN6",
        "rb_name": "GUEST6-WAN6",
        "af": 6,
        "default_action": None,
        "src_zone": "GUEST",
        "dst_zone": "WAN",
        "zone_default": "drop",
    }
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", lambda s, q, **p: [v6_row] if "FROM_ZONE" in q else [])
    src, dst = path._intervals(["192.168.110.53"]), path._intervals(["8.8.8.8"])
    v = path._zone_pair_verdict(None, "if:in", "if:out", src, dst, 443, "tcp", 4)
    assert classify_action(v["action"]) == DENY
    assert v["by"] == "default-action"
    assert "GUEST6-WAN6" not in v["rb_name"] and v["rb_uid"] is None


def test_zone_rule_with_neither_objects_nor_any_is_undecided(monkeypatch):
    """The empty-collection rule holds in the zone model too: vyos.py makes the
    vendor's implicit Any explicit as `src_any`/`dst_any`, so a rule carrying
    neither objects nor the flag is a side the gate cannot read, not a miss, and
    the zone default does not decide past it."""
    zone_row = {
        "rb_uid": "rb:z",
        "rb_name": "lan-wan",
        "default_action": None,
        "src_zone": "lan",
        "dst_zone": "wan",
        "zone_default": None,
    }
    rules = [_rule(uid="z:r1", pos=1, action="accept")]  # no objects, no any flags

    def read(s, q, **p):
        if "FROM_ZONE" in q:
            return [zone_row] if p.get("in_if") == "if:in" and p.get("out_if") == "if:out" else []
        return rules if "HAS_RULE" in q else []

    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", read)
    src, dst = path._intervals(["10.0.0.0/24"]), path._intervals(["10.9.9.0/24"])
    v = path._zone_pair_verdict(None, "if:in", "if:out", src, dst, 443, "tcp", 4)
    assert v["rule_uid"] == "z:r1"
    assert classify_action(v["action"]) == INDETERMINATE
    assert path._zone_pair_verdict(None, "if:out", "if:in", src, dst, 443, "tcp", 4) is None


def test_zone_pair_leg_note_names_the_reason_when_a_side_carries_no_address(monkeypatch):
    from hst.path.gates.firewall import _apply_firewall

    zone_row = {
        "rb_uid": "vyos:gw:fw:LAN-WAN",
        "rb_name": "LAN-WAN",
        "af": 4,
        "default_action": None,
        "src_zone": "lan",
        "dst_zone": "wan",
        "zone_default": None,
    }
    rules = [_rule(uid="z:r1", pos=1, action="drop", src_obj_count=1, dst_any=True, svc_any=True)]

    def fake_read(s, q, **p):
        # the zone-pair read only: the device-wide candidate query names
        # FROM_ZONE too (it excludes zone-bound rulebases), and this device
        # carries no device-wide chain
        if "FROM_ZONE]->(src)" in q:
            return [zone_row]
        return rules if "HAS_RULE" in q else []

    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", fake_read)

    trail, leg = path._Trail(), {}
    _apply_firewall(
        None,
        trail,
        leg,
        {"dev_uid": "dev:fw1", "if_uid": "if:in"},
        "if:out",
        path._intervals(["10.0.0.0/24"]),
        path._intervals(["10.9.9.0/24"]),
        443,
        "tcp",
        "10.0.0.0/24",
        "eth0",
    )
    assert leg["indeterminate"] is True
    note = " ".join(trail.warnings)
    assert "referenced objects carry no address" in note
    assert "does not evaluate" not in note


def test_an_unresolved_vendor_action_is_indeterminate_not_permitted(graph):
    graph["rules"] = [
        _rule(action="97aeb369-9aea-11d5-bd16-0090272ccb30", src_any=True, dst_any=True, svc_any=True)
    ]
    assert classify_action(_verdict()["action"]) == INDETERMINATE


def test_an_approximate_binding_never_yields_a_confident_verdict(graph):
    graph["rb"] = {**RB, "approximate": True}
    graph["rules"] = [_rule(action="drop", src_any=True, dst_any=True, svc_any=True)]
    v = _verdict()
    assert v["action"] == INDETERMINATE
    assert v["approximate_binding"] is True
    assert v["rule_uid"] == "cp:r1"


# --- ACI contracts -----------------------------------------------------------------------


_COLLECTED_ENTRY = {
    "s_from_port": "unspecified",
    "s_to_port": "unspecified",
    "tcp_rules": "unspecified",
    "apply_to_frag": "no",
}


def _as_collected(contracts):
    return [
        {**row, "entries": [{**_COLLECTED_ENTRY, **entry} for entry in row.get("entries") or ()]}
        for row in contracts
    ]


@pytest.fixture()
def aci(monkeypatch):
    state = {"ends": [], "contracts": []}

    def fake_read(session, query, **params):
        if "IN_EPG" in query:
            return state["ends"]
        if "CONSUMES" in query:
            return _as_collected(state["contracts"])
        return []

    monkeypatch.setattr(path, "_read", fake_read)
    return state


def _ends(src_epg="epg:web", dst_epg="epg:db", vrf_uid="vrf:common", pc_enf_pref="enforced"):
    return [
        {
            "ip": "10.0.0.5",
            "epg_uid": src_epg,
            "epg_name": (src_epg or "").split(":")[-1],
            "vrf_uid": vrf_uid,
            "pc_enf_pref": pc_enf_pref,
            "contract_bypass": "",
        },
        {
            "ip": "10.9.9.5",
            "epg_uid": dst_epg,
            "epg_name": (dst_epg or "").split(":")[-1],
            "vrf_uid": vrf_uid,
            "pc_enf_pref": pc_enf_pref,
            "contract_bypass": "",
        },
    ]


def _aci(port=1521, proto="tcp"):
    return path.aci_contract_verdict(None, "10.0.0.5", "10.9.9.5", port, proto)


def test_neither_end_in_an_epg_says_nothing(aci):
    aci["ends"] = []
    assert _aci() is None


def test_one_end_in_an_epg_is_indeterminate(aci):
    aci["ends"] = [{"ip": "10.0.0.5", "epg_uid": "epg:web", "epg_name": "web"}]
    assert _aci()["action"] == INDETERMINATE


def test_no_contract_between_the_epgs_denies(aci):
    aci["ends"] = _ends()
    aci["contracts"] = []
    v = _aci()
    assert v["action"] == DENY and "no contract" in v["reason"]


def test_a_matching_filter_entry_permits(aci):
    aci["ends"] = _ends()
    aci["contracts"] = [
        {"uid": "k1", "name": "web-to-db", "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521}]}
    ]
    v = _aci(port=1521)
    assert v["action"] == PERMIT and v["contract"] == "web-to-db"


def test_an_entry_with_no_action_key_permits(aci):
    aci["ends"] = _ends()
    aci["contracts"] = [
        {"uid": "k1", "name": "web-to-db", "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521}]}
    ]
    v = _aci(port=1521)
    assert v["action"] == PERMIT


def test_a_deny_filter_beats_a_co_matching_permit_filter_in_the_same_contract(aci):
    aci["ends"] = _ends()
    aci["contracts"] = [
        {
            "uid": "k1",
            "name": "web-to-db",
            "entries": [
                {"proto": "tcp", "from_port": 1521, "to_port": 1521, "action": "permit"},
                {"proto": "tcp", "from_port": 1521, "to_port": 1521, "action": "DENY"},
            ],
        }
    ]
    v = _aci(port=1521)
    assert v["action"] == DENY
    assert "web-to-db" in v["reason"] and "deny" in v["reason"].lower() and "permit" in v["reason"].lower()
    assert v["contract_uid"] == "k1" and v["contract_uids"] == ["k1"]


def test_a_service_graph_redirect_beats_a_co_matching_deny_filter(aci):
    aci["ends"] = _ends()
    aci["contracts"] = [
        {
            "uid": "k1",
            "name": "web-to-db",
            "entries": [
                {"proto": "tcp", "from_port": 1521, "to_port": 1521, "action": "deny"},
                {"proto": "tcp", "from_port": 1521, "to_port": 1521, "graph": "fw-insert"},
            ],
        }
    ]
    v = _aci(port=1521)
    assert v["action"] == INDETERMINATE
    assert "fw-insert" in v["reason"] and "service graph redirect not evaluated" in v["reason"]


def test_a_service_graph_redirect_wins_regardless_of_entry_order(aci):
    """The 'any matching entry carries a graph' rule must not depend on collect()'s
    row order."""
    aci["ends"] = _ends()
    entries = [
        {"proto": "tcp", "from_port": 1521, "to_port": 1521},
        {"proto": "tcp", "from_port": 1521, "to_port": 1521, "graph": "fw-insert"},
    ]
    aci["contracts"] = [{"uid": "k1", "name": "web-to-db", "entries": entries}]
    assert _aci(port=1521)["action"] == INDETERMINATE
    aci["contracts"] = [{"uid": "k1", "name": "web-to-db", "entries": list(reversed(entries))}]
    assert _aci(port=1521)["action"] == INDETERMINATE


def test_an_unrecognized_action_is_indeterminate_not_a_guess(aci):
    aci["ends"] = _ends()
    aci["contracts"] = [
        {
            "uid": "k1",
            "name": "web-to-db",
            "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521, "action": "log"}],
        }
    ]
    v = _aci(port=1521)
    assert v["action"] == INDETERMINATE
    assert "log" in v["reason"]


def test_a_contract_whose_entries_do_not_match_the_port_denies(aci):
    aci["ends"] = _ends()
    aci["contracts"] = [
        {"uid": "k1", "name": "web-to-db", "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521}]}
    ]
    assert _aci(port=443)["action"] == DENY


def test_unspecified_is_the_aci_wildcard(aci):
    aci["ends"] = _ends()
    aci["contracts"] = [
        {"uid": "k1", "name": "permit-any", "entries": [{"proto": "unspecified", "from_port": "unspecified"}]}
    ]
    assert _aci(port=443)["action"] == PERMIT


def test_a_contract_with_no_collected_entries_is_indeterminate(aci):
    aci["ends"] = _ends()
    aci["contracts"] = [{"uid": "k1", "name": "empty", "entries": []}]
    assert _aci()["action"] == INDETERMINATE


def test_intra_epg_is_indeterminate_because_isolation_is_not_collected(aci):
    aci["ends"] = _ends(src_epg="epg:web", dst_epg="epg:web")
    assert _aci()["action"] == INDETERMINATE


def test_every_contract_is_examined_before_concluding(aci):
    """The first contract's failure to match must not decide for the pair."""
    aci["ends"] = _ends()
    aci["contracts"] = [
        {"uid": "k1", "name": "ssh-only", "entries": [{"proto": "tcp", "from_port": 22, "to_port": 22}]},
        {"uid": "k2", "name": "web-to-db", "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521}]},
    ]
    v = _aci(port=1521)
    assert v["action"] == PERMIT and v["contract"] == "web-to-db"


def test_an_uncollected_contract_beside_a_permit_is_indeterminate(aci):
    aci["ends"] = _ends()
    aci["contracts"] = [
        {"uid": "k1", "name": "empty", "entries": []},
        {"uid": "k2", "name": "web-to-db", "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521}]},
    ]
    v = _aci(port=1521)
    assert v["action"] == INDETERMINATE
    assert v["contract"] == "empty"


def test_indeterminate_names_the_uncollected_contract_after_examining_the_rest(aci):
    aci["ends"] = _ends()
    aci["contracts"] = [
        {"uid": "k1", "name": "empty", "entries": []},
        {"uid": "k2", "name": "ssh-only", "entries": [{"proto": "tcp", "from_port": 22, "to_port": 22}]},
    ]
    v = _aci(port=443)
    assert v["action"] == INDETERMINATE
    assert v["contract"] == "empty" and v["contract_uid"] == "k1"


def test_deny_names_every_examined_contract(aci):
    aci["ends"] = _ends()
    aci["contracts"] = [
        {"uid": "k1", "name": "ssh-only", "entries": [{"proto": "tcp", "from_port": 22, "to_port": 22}]},
        {"uid": "k2", "name": "web-to-db", "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521}]},
    ]
    v = _aci(port=443)
    assert v["action"] == DENY
    assert "2 contracts apply" in v["reason"]
    assert "ssh-only" in v["reason"] and "web-to-db" in v["reason"]
    assert set(v["contract_uids"]) == {"k1", "k2"}


@pytest.mark.parametrize("port,expected", [(1521, PERMIT), (443, DENY)])
def test_a_verdict_that_examined_a_contract_carries_its_uid(aci, port, expected):
    aci["ends"] = _ends()
    aci["contracts"] = [
        {"uid": "k1", "name": "web-to-db", "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521}]}
    ]
    v = _aci(port=port)
    assert v["action"] == expected
    assert v["contract_uid"] == "k1"
    assert v["contract_uids"] == ["k1"]


# --- ACI VRF enforcement ---------------------------------------------------------------------------


def test_enforced_vrf_denies_with_no_contract_proven(aci):
    aci["ends"] = _ends(pc_enf_pref="enforced")
    aci["contracts"] = []
    v = _aci()
    assert v["action"] == DENY and "no contract" in v["reason"]


def test_unenforced_vrf_permits_with_no_contract_proven(aci):
    """ACI does not consult contracts inside an unenforced VRF: absent a proven permit,
    the flow is permitted, and the reason names the VRF as unenforced."""
    aci["ends"] = _ends(pc_enf_pref="unenforced")
    aci["contracts"] = []
    v = _aci()
    assert v["action"] == PERMIT
    assert "unenforced" in v["reason"]


def test_unenforced_vrf_permits_even_when_a_contract_does_not_match(aci):
    aci["ends"] = _ends(pc_enf_pref="unenforced")
    aci["contracts"] = [
        {"uid": "k1", "name": "ssh-only", "entries": [{"proto": "tcp", "from_port": 22, "to_port": 22}]}
    ]
    v = _aci(port=443)
    assert v["action"] == PERMIT
    assert v["contract_uids"] == ["k1"]


def test_unknown_enforcement_because_the_epgs_are_in_different_vrfs_is_indeterminate(aci):
    aci["ends"] = [
        {
            "ip": "10.0.0.5",
            "epg_uid": "epg:web",
            "epg_name": "web",
            "vrf_uid": "vrf:a",
            "pc_enf_pref": "enforced",
        },
        {
            "ip": "10.9.9.5",
            "epg_uid": "epg:db",
            "epg_name": "db",
            "vrf_uid": "vrf:b",
            "pc_enf_pref": "enforced",
        },
    ]
    aci["contracts"] = []
    assert _aci()["action"] == INDETERMINATE


def test_unknown_enforcement_because_pc_enf_pref_was_not_collected_is_indeterminate(aci):
    aci["ends"] = _ends(pc_enf_pref=None)
    aci["contracts"] = []
    assert _aci()["action"] == INDETERMINATE


def test_an_unrecognized_pc_enf_pref_value_is_indeterminate_not_a_guess(aci):
    aci["ends"] = _ends(pc_enf_pref="learning")
    aci["contracts"] = [
        {"uid": "k1", "name": "web-to-db", "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521}]}
    ]
    v = _aci(port=443)  # no matching entry -> falls through to the enforcement-gated branch
    assert v["action"] == INDETERMINATE


def test_unenforced_vrf_permits_even_when_a_contract_would_have_proven_permit(aci):
    aci["ends"] = _ends(pc_enf_pref="unenforced")
    aci["contracts"] = [
        {"uid": "k1", "name": "web-to-db", "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521}]}
    ]
    v = _aci(port=1521)
    assert v["action"] == PERMIT
    assert v["contract"] is None and v["contract_uid"] is None
    assert v["contract_uids"] == ["k1"]
    assert "unenforced" in v["reason"]


def test_unenforced_vrf_permits_a_matching_deny(aci):
    """Real ACI does not apply contracts in an unenforced VRF: a matching deny entry
    must not decide anything before the enforcement check runs."""
    aci["ends"] = _ends(pc_enf_pref="unenforced")
    aci["contracts"] = [
        {
            "uid": "k1",
            "name": "web-to-db",
            "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521, "action": "deny"}],
        }
    ]
    v = _aci(port=1521)
    assert v["action"] == PERMIT
    assert "unenforced" in v["reason"]


def test_unenforced_vrf_permits_a_matching_service_graph_redirect(aci):
    """Same as a matching deny: a service graph redirect on a matching entry must not
    decide anything before the unenforced short-circuit runs."""
    aci["ends"] = _ends(pc_enf_pref="unenforced")
    aci["contracts"] = [
        {
            "uid": "k1",
            "name": "web-to-db",
            "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521, "graph": "fw-insert"}],
        }
    ]
    v = _aci(port=1521)
    assert v["action"] == PERMIT
    assert "unenforced" in v["reason"]


def test_an_ip_in_more_than_one_epg_is_indeterminate_not_a_pick(aci):
    rows = [
        {"ip": "10.0.0.5", "epg_uid": "epg:zz", "epg_name": "zz", "vrf_uid": "vrf:b"},
        {"ip": "10.0.0.5", "epg_uid": "epg:aa", "epg_name": "aa", "vrf_uid": "vrf:a"},
        {"ip": "10.9.9.5", "epg_uid": "epg:db", "epg_name": "db", "vrf_uid": "vrf:a"},
    ]
    aci["ends"] = rows
    aci["contracts"] = [
        {"uid": "k1", "name": "web-to-db", "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521}]}
    ]
    v = _aci()
    assert v["action"] == INDETERMINATE
    assert "10.0.0.5 has multiple EPG identities" in v["reason"]
    aci["ends"] = list(reversed(rows))
    assert _aci()["action"] == INDETERMINATE


def test_the_trace_context_scopes_an_ip_reused_across_vrfs(aci):
    """The VRF the trace drew the flow through names the EPG of an
    address another tenant's VRF reuses."""
    rows = [
        {"ip": "10.0.0.5", "epg_uid": "epg:zz", "epg_name": "zz", "vrf_uid": "vrf:b"},
        *_ends(src_epg="epg:web", vrf_uid="vrf:a"),
    ]
    aci["ends"] = rows
    aci["contracts"] = [
        {"uid": "k1", "name": "web-to-db", "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521}]}
    ]
    v = path.aci_contract_verdict(None, "10.0.0.5", "10.9.9.5", 1521, "tcp", ["vrf:a"])
    assert v["action"] == PERMIT
    assert v["epgs"] == "web→db"


# --- zone pair with no ruleset bound --------------------------------------------------------------


def _zones(monkeypatch, zones: dict[str, dict]):
    """Script the per-interface zone lookup; no zone pair rulebase exists."""

    def fake_read_one(s, q, **p):
        if "CONTAINS]-(z:Zone)" in q:
            return zones.get(p["in_if"])
        return None

    monkeypatch.setattr(path, "_read_one", fake_read_one)
    monkeypatch.setattr(path, "_read", lambda s, q, **p: [])


def test_two_zones_with_no_ruleset_bound_drop_by_the_destination_zone_default(monkeypatch):
    _zones(
        monkeypatch,
        {
            "if:in": {"name": "LAN", "default_action": None},
            "if:out": {"name": "WAN", "default_action": "drop"},
        },
    )
    src, dst = path._intervals(["10.0.0.5"]), path._intervals(["8.8.8.8"])
    v = path._zone_pair_verdict(None, "if:in", "if:out", src, dst, 443, "tcp", 4)
    assert v is not None
    assert classify_action(v["action"]) == DENY
    assert v["by"] == "default-action"
    # a synthetic station uid, so the block is drawn even though no rulebase node exists
    assert v["rb_uid"] == "zone-pair:LAN->WAN#unbound"
    assert v["zones"] == "LAN→WAN"


def test_an_unbound_pair_into_a_zone_stating_no_default_is_undecided(monkeypatch):
    _zones(
        monkeypatch,
        {"if:in": {"name": "LAN", "default_action": None}, "if:out": {"name": "WAN", "default_action": None}},
    )
    src, dst = path._intervals(["10.0.0.5"]), path._intervals(["8.8.8.8"])
    v = path._zone_pair_verdict(None, "if:in", "if:out", src, dst, 443, "tcp", 4)
    assert v["by"] == "default-action"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == _UNSTATED_DEFAULT


def test_an_unbound_pair_honours_a_configured_destination_default(monkeypatch):
    _zones(
        monkeypatch,
        {
            "if:in": {"name": "LAN", "default_action": None},
            "if:out": {"name": "DMZ", "default_action": "accept"},
        },
    )
    src, dst = path._intervals(["10.0.0.5"]), path._intervals(["10.9.0.9"])
    v = path._zone_pair_verdict(None, "if:in", "if:out", src, dst, 443, "tcp", 4)
    assert classify_action(v["action"]) == PERMIT and v["by"] == "default-action"


def test_same_zone_traffic_is_not_judged_by_zone_policy(monkeypatch):
    _zones(
        monkeypatch,
        {"if:in": {"name": "LAN", "default_action": None}, "if:out": {"name": "LAN", "default_action": None}},
    )
    src, dst = path._intervals(["10.0.0.5"]), path._intervals(["10.0.1.5"])
    assert path._zone_pair_verdict(None, "if:in", "if:out", src, dst, 443, "tcp", 4) is None


def test_an_egress_in_no_zone_yields_no_pair_verdict(monkeypatch):
    """The pair cannot be formed; the trace layer reports that as indeterminate."""
    _zones(monkeypatch, {"if:in": {"name": "LAN", "default_action": None}})
    src, dst = path._intervals(["10.0.0.5"]), path._intervals(["8.8.8.8"])
    assert path._zone_pair_verdict(None, "if:in", "if:out", src, dst, 443, "tcp", 4) is None


# --- the three-valued proto/port comparison ----------------------------------------------

_NO_PROTO = "the query carries no protocol, and this rule's service is scoped to one"
_NO_PORT = "the query carries no destination port, and this rule's service is scoped to one"


class TestProtoMatchGrammar:
    """`_proto_matches` reads one VyOS protocol spec, negation included."""

    @pytest.mark.parametrize(
        ("specs", "proto", "expected"),
        [
            ([], "tcp", _MATCH),
            ([], None, _MATCH),
            (["tcp"], "tcp", _MATCH),
            (["tcp"], "udp", _NO_MATCH),
            (["tcp_udp"], "udp", _MATCH),
            (["tcp-udp"], "tcp", _MATCH),
            (["all"], "gre", _MATCH),
            (["all"], None, _MATCH),
            (["tcp"], None, _UNKNOWN),
        ],
        ids=[
            "unconstrained",
            "unconstrained-and-no-protocol",
            "plain-hit",
            "plain-miss",
            "compound-underscore",
            "compound-hyphen",
            "all",
            "all-constrains-nothing-so-no-protocol-is-needed",
            "scoped-against-a-protocol-less-query",
        ],
    )
    def test_plain_specs(self, specs, proto, expected):
        assert _proto_matches(specs, proto) == expected

    @pytest.mark.parametrize(
        ("specs", "proto", "expected"),
        [
            (["!tcp"], "udp", _MATCH),
            (["!tcp"], "tcp", _NO_MATCH),
            (["! tcp"], "tcp", _NO_MATCH),
            (["!tcp_udp"], "udp", _NO_MATCH),
            (["!tcp_udp"], "icmp", _MATCH),
            (["!all"], "tcp", _NO_MATCH),
            (["!all"], None, _NO_MATCH),
            (["!tcp", "udp"], "tcp", _NO_MATCH),
            (["!tcp"], None, _UNKNOWN),
        ],
        ids=[
            "negated-covers-everything-else",
            "negated-excludes-its-own",
            "negated-tolerates-a-space",
            "negated-compound-excludes-both",
            "negated-compound-covers-the-rest",
            "negated-all-covers-nothing",
            "negated-all-covers-nothing-whatever-the-query-carries",
            "negated-and-plain-are-ored",
            "negated-against-a-protocol-less-query",
        ],
    )
    def test_negated_specs(self, specs, proto, expected):
        assert _proto_matches(specs, proto) == expected

    @pytest.mark.parametrize(
        ("specs", "proto", "expected"),
        [
            (["tcp"], "6", _MATCH),
            (["icmp6"], "icmpv6", _MATCH),
            (["253"], "254", _NO_MATCH),
            (["fooproto"], "6", _UNKNOWN),
            (["!fooproto"], "6", _UNKNOWN),
            (["fooproto", "tcp"], "6", _MATCH),
            (["fooproto", "udp"], "6", _UNKNOWN),
        ],
        ids=[
            "query-number-meets-member-name",
            "query-alias-meets-member-other-alias",
            "distinct-numbers-still-miss",
            "unresolvable-rule-spec-beside-a-resolvable-query-number-is-undecided",
            "negated-unresolvable-rule-spec-is-undecided-not-a-match",
            "a-resolvable-spec-beside-it-still-matches",
            "a-resolvable-spec-beside-it-that-misses-leaves-it-undecided",
        ],
    )
    def test_number_fallback(self, specs, proto, expected):
        assert _proto_matches(specs, proto) == expected


class TestPortMatchStates:
    @pytest.mark.parametrize(
        ("spec", "port", "expected"),
        [
            (None, 443, _MATCH),
            ("", 443, _MATCH),
            ([], None, _MATCH),
            ("443", 443, _MATCH),
            ("80,443", 443, _MATCH),
            ("1000-2000", 1500, _MATCH),
            (["80", "443"], 443, _MATCH),
            ("443", 80, _NO_MATCH),
            ("443", None, _UNKNOWN),
            (["80", "443"], None, _UNKNOWN),
            ("http", 80, _UNKNOWN),
            ("http,443", 443, _MATCH),
            ("2000-1000", 1500, _UNKNOWN),
            ("a-b", 80, _UNKNOWN),
        ],
    )
    def test_states(self, spec, port, expected):
        assert _port_matches(spec, port) == expected


class TestCombine:
    def test_and_takes_a_definite_miss_before_anything_else(self):
        """One member's own (proto, port) pair: a definite miss on either
        dimension decides it, whatever the other dimension turns out to be."""
        assert _combine_and(_NO_MATCH, _UNKNOWN) == _NO_MATCH
        assert _combine_and(_UNKNOWN, _NO_MATCH) == _NO_MATCH
        assert _combine_and(_MATCH, _UNKNOWN) == _UNKNOWN
        assert _combine_and(_MATCH, _MATCH) == _MATCH
        assert _combine_and() == _MATCH

    def test_or_takes_a_definite_hit_before_anything_else(self):
        assert _combine_or(_MATCH, _UNKNOWN) == _MATCH
        assert _combine_or(_NO_MATCH, _UNKNOWN) == _UNKNOWN
        assert _combine_or(_NO_MATCH, _NO_MATCH) == _NO_MATCH
        assert _combine_or() == _NO_MATCH


def test_a_protocol_scoped_rule_against_a_protocol_less_query_is_indeterminate(graph):
    graph["rules"] = [
        _rule(uid="cp:r1", pos=1, action="drop", src_any=True, dst_any=True, protos=["tcp"]),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(proto=None)
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == _NO_PROTO


def test_a_port_scoped_rule_against_a_port_less_query_is_indeterminate(graph):
    graph["rules"] = [
        _rule(uid="cp:r1", pos=1, action="drop", src_any=True, dst_any=True, ports=["443"]),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(port=None)
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == _NO_PORT


def test_both_missing_dimensions_are_named_in_the_reason(graph):
    graph["rules"] = [
        _rule(uid="cp:r1", pos=1, action="drop", src_any=True, dst_any=True, protos=["tcp"], ports=["443"]),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(port=None, proto=None)
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == f"{_NO_PROTO}; {_NO_PORT}"


def test_a_missing_dimension_is_decided_before_the_service_negation(graph):
    """The same order opacity is decided in: complementing a side that could
    not be read leaves it unread. A negated protocol-scoped rule against a
    protocol-less query is undecided, not a confident non-match."""
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            protos=["tcp"],
            svc_negate=True,
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(proto=None)
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == _NO_PROTO


def test_a_missing_dimension_does_not_disturb_a_rule_that_plainly_misses(graph):
    graph["rules"] = [
        _rule(uid="cp:r1", pos=1, action="drop", src_any=True, dst_any=True, ports=["443"]),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(port=80, proto=None)
    assert v["rule_uid"] == "cp:r2"
    assert classify_action(v["action"]) == PERMIT


def test_the_leg_note_names_the_missing_protocol(graph):
    note = _leg_note(
        graph,
        _rule(action="drop", src_any=True, dst_any=True, protos=["tcp"]),
        proto=None,
    )
    assert _NO_PROTO in note
    assert "does not evaluate" not in note


def test_the_leg_note_names_the_missing_destination_port(graph):
    note = _leg_note(
        graph,
        _rule(action="drop", src_any=True, dst_any=True, ports=["443"]),
        port=None,
    )
    assert _NO_PORT in note
    assert "does not evaluate" not in note


def test_a_negated_protocol_spec_matches_the_complement(graph):
    """`protocol !tcp` covers udp and not
    tcp, without the rule having to carry svc_negate."""
    graph["rules"] = [
        _rule(uid="cp:r1", pos=1, action="drop", src_any=True, dst_any=True, protos=["!tcp"]),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    assert _verdict(proto="tcp")["rule_uid"] == "cp:r2"
    assert _verdict(proto="udp")["rule_uid"] == "cp:r1"


# --- one member's protocol goes with that member's port ----------------------------------


def test_a_service_group_does_not_match_a_crossed_member_pairing(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="accept",
            src_any=True,
            dst_any=True,
            svc_obj_count=1,
            protos=["tcp", "udp"],
            ports=["443", "53"],
        ),
        _rule(uid="cp:r2", pos=2, action="drop", src_any=True, dst_any=True, svc_any=True),
    ]
    # the crossed pairing: tcp is member 0's protocol, 53 is member 1's port
    assert _verdict(port=53, proto="tcp")["rule_uid"] == "cp:r2"
    assert _verdict(port=443, proto="tcp")["rule_uid"] == "cp:r1"
    assert _verdict(port=53, proto="udp")["rule_uid"] == "cp:r1"


def test_a_member_with_a_port_and_no_protocol_matches_any_protocol_on_that_port(graph):
    """A VyOS port-group SvcObject carries ports and no proto, so its slot in
    `protos` is null. A null means that dimension is unconstrained for that
    member, not that the member is missing."""
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="accept",
            src_any=True,
            dst_any=True,
            svc_obj_count=1,
            protos=[None],
            ports=["443"],
        ),
        _rule(uid="cp:r2", pos=2, action="drop", src_any=True, dst_any=True, svc_any=True),
    ]
    assert _verdict(port=443, proto="udp")["rule_uid"] == "cp:r1"
    assert _verdict(port=443, proto="tcp")["rule_uid"] == "cp:r1"
    assert _verdict(port=80, proto="tcp")["rule_uid"] == "cp:r2"


def test_a_member_with_a_protocol_and_no_port_matches_any_port_of_it(graph):
    """The mirror shape: an ip-protocol service carries a proto and no ports."""
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="accept",
            src_any=True,
            dst_any=True,
            svc_obj_count=1,
            protos=["tcp", "udp"],
            ports=[None, "53"],
        ),
        _rule(uid="cp:r2", pos=2, action="drop", src_any=True, dst_any=True, svc_any=True),
    ]
    assert _verdict(port=9999, proto="tcp")["rule_uid"] == "cp:r1"
    assert _verdict(port=9999, proto="udp")["rule_uid"] == "cp:r2"


def test_a_member_constraining_neither_dimension_drops_out_as_a_pair(graph):
    """The 0-hop member of the MEMBER_OF traversal is the service group's own
    node, and it carries no proto and no ports of its own. Read as a pair it
    would be a member constraining nothing, and one such member would make the
    rule match every flow; it drops out and the real members decide."""
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="accept",
            src_any=True,
            dst_any=True,
            svc_obj_count=1,
            protos=[None, "tcp"],
            ports=[None, "443"],
        ),
        _rule(uid="cp:r2", pos=2, action="drop", src_any=True, dst_any=True, svc_any=True),
    ]
    assert _verdict(port=443, proto="tcp")["rule_uid"] == "cp:r1"
    assert _verdict(port=80, proto="tcp")["rule_uid"] == "cp:r2"


def test_an_undecidable_member_leaves_the_whole_service_side_undecided(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            svc_obj_count=1,
            protos=["tcp", "udp"],
            ports=["443", "53"],
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    # the control: with the protocol known, tcp/80 misses both members outright
    assert _verdict(port=80, proto="tcp")["rule_uid"] == "cp:r2"
    v = _verdict(port=53, proto=None)
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE


# --- a chain that never recorded its default action --------------------------------------

_UNKNOWN_DEFAULT = "the chain's default action is not recorded"
_UNSTATED_DEFAULT = "the collection states neither the default action nor that it is unrecorded"


def test_an_unrecorded_chain_default_is_indeterminate_not_a_drop(graph):
    graph["rb"] = {**RB, "vendor": "vyos", "default_action": None, "default_action_unknown": True}
    graph["rules"] = [_rule(src_cidrs=["192.168.0.0/24"], dst_any=True, svc_any=True)]
    v = _verdict()
    assert v["by"] == "default-action"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == _UNKNOWN_DEFAULT


def test_a_recorded_chain_default_decides(graph):
    graph["rb"] = {**RB, "vendor": "vyos", "default_action": "drop", "default_action_unknown": False}
    graph["rules"] = [_rule(src_cidrs=["192.168.0.0/24"], dst_any=True, svc_any=True)]
    v = _verdict()
    assert v["by"] == "default-action"
    assert classify_action(v["action"]) == DENY
    assert v["indeterminate_reason"] is None


def test_a_matched_rule_is_unaffected_by_an_unrecorded_chain_default(graph):
    """The marker governs the fall-through only; a rule that matches answers
    with its own action."""
    graph["rb"] = {**RB, "vendor": "vyos", "default_action": None, "default_action_unknown": True}
    graph["rules"] = [_rule(action="accept", src_any=True, dst_any=True, svc_any=True)]
    v = _verdict()
    assert v["by"] == "rule"
    assert classify_action(v["action"]) == PERMIT


def test_a_zone_bound_ruleset_with_no_recorded_default_does_not_borrow_the_zone_default(monkeypatch):
    row = {
        "rb_uid": "vyos:gw:fw:GUEST-WAN",
        "rb_name": "GUEST-WAN",
        "af": 4,
        "default_action": None,
        "default_action_unknown": True,
        "src_zone": "GUEST",
        "dst_zone": "WAN",
        "zone_default": "drop",
    }
    rules = [_rule(uid="z:r1", pos=1, action="accept", src_cidrs=["192.168.0.0/24"], dst_any=True)]

    def read(s, q, **p):
        if "FROM_ZONE" in q:
            return [row]
        return rules if "HAS_RULE" in q else []

    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", read)
    src, dst = path._intervals(["192.168.110.53"]), path._intervals(["8.8.8.8"])
    v = path._zone_pair_verdict(None, "if:in", "if:out", src, dst, 443, "tcp", 4)
    assert v["by"] == "default-action"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == _UNKNOWN_DEFAULT


def test_a_zone_bound_ruleset_that_recorded_its_default_decides(monkeypatch):
    row = {
        "rb_uid": "vyos:gw:fw:GUEST-WAN",
        "rb_name": "GUEST-WAN",
        "af": 4,
        "default_action": "accept",
        "default_action_unknown": False,
        "src_zone": "GUEST",
        "dst_zone": "WAN",
        "zone_default": "drop",
    }
    rules = [_rule(uid="z:r1", pos=1, action="drop", src_cidrs=["192.168.0.0/24"], dst_any=True)]

    def read(s, q, **p):
        if "FROM_ZONE" in q:
            return [row]
        return rules if "HAS_RULE" in q else []

    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", read)
    src, dst = path._intervals(["192.168.110.53"]), path._intervals(["8.8.8.8"])
    v = path._zone_pair_verdict(None, "if:in", "if:out", src, dst, 443, "tcp", 4)
    assert v["by"] == "default-action"
    assert classify_action(v["action"]) == PERMIT


# --- a device-wide forward chain beside a zone policy -----------------------------------

_ZONE_MODEL = {
    "rb_uid": "vyos:gw:fw:LAN-WAN",
    "rb_name": "LAN-WAN",
    "af": 4,
    "default_action": "drop",
    "default_action_unknown": False,
    "global_state_policy": None,
    "src_zone": "LAN",
    "dst_zone": "WAN",
    "zone_default": "drop",
    "zone_default_unknown": False,
}

_CHAIN_MODEL = {
    "rb_uid": "vyos:gw:fw:ipv4-forward",
    "rb_name": "ipv4-forward",
    "vendor": "vyos",
    "af": 4,
    "default_action": "drop",
    "default_action_unknown": False,
    "global_state_policy": None,
    "match_context": None,
    "chain": "forward",
    "approximate": False,
}


def _both_models(monkeypatch, chain_rules, zone_rules):
    """A device carrying both rulebase models, each with its own rules."""

    def read(s, q, **p):
        # the device-wide candidate query names FROM_ZONE too (it excludes
        # zone-bound rulebases), so the zone-pair read is matched on the
        # pattern only it carries
        if "FROM_ZONE]->(src)" in q:
            return [_ZONE_MODEL]
        if "coalesce(rb.chain, 'forward') = $chain" in q:
            return [_CHAIN_MODEL]
        if "HAS_RULE" in q:
            return chain_rules if p.get("rb") == _CHAIN_MODEL["rb_uid"] else zone_rules
        return []

    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", read)


def _accept_all(uid):
    return [_rule(uid=uid, pos=10, action="accept", src_any=True, dst_any=True, svc_any=True)]


def _drop_all(uid):
    return [_rule(uid=uid, pos=10, action="drop", src_any=True, dst_any=True, svc_any=True)]


def _both_models_verdict(monkeypatch, chain_rules, zone_rules, considered=None):
    _both_models(monkeypatch, chain_rules, zone_rules)
    return firewall._firewall_verdict(
        None,
        "dev:gw",
        "if:in",
        "if:out",
        path._intervals(["10.20.1.50"]),
        path._intervals(["10.0.30.10"]),
        443,
        "tcp",
        considered,
    )


def test_a_forward_chain_and_a_zone_pair_that_both_permit_are_both_credited(monkeypatch):
    """Both rulebases govern the packet, so both are evaluated and both are
    credited: the one that did not decide is examined, not unexamined, and
    must not reach the unevaluated-gate safeguard."""
    considered = []
    v = _both_models_verdict(
        monkeypatch, _accept_all("fwd:10"), _accept_all("zone:10"), considered=considered
    )
    assert classify_action(v["action"]) == PERMIT
    # the device's own order: nftables runs the forward chain's rules before
    # it jumps to the zone-pair chain
    assert [m["rb_uid"] for m in v["models"]] == ["vyos:gw:fw:ipv4-forward", "vyos:gw:fw:LAN-WAN"]
    assert sorted(considered) == ["vyos:gw:fw:LAN-WAN", "vyos:gw:fw:ipv4-forward"]


def test_a_deny_in_the_forward_chain_decides_over_a_permitting_zone_pair(monkeypatch):
    """A deny from either rulebase is the verdict: the packet has to pass both."""
    v = _both_models_verdict(monkeypatch, _drop_all("fwd:10"), _accept_all("zone:10"))
    assert classify_action(v["action"]) == DENY
    assert v["rb_uid"] == "vyos:gw:fw:ipv4-forward"
    assert v["rule_uid"] == "fwd:10"


def test_a_deny_in_the_zone_pair_decides_over_a_permitting_forward_chain(monkeypatch):
    """The same rule in the other direction: the chain permits, the zone pair
    denies, and the zone pair is what the leg names as the decider."""
    v = _both_models_verdict(monkeypatch, _accept_all("fwd:10"), _drop_all("zone:10"))
    assert classify_action(v["action"]) == DENY
    assert v["rb_uid"] == "vyos:gw:fw:LAN-WAN"
    assert v["rule_uid"] == "zone:10"


def test_a_leg_across_both_models_draws_both_stations_and_names_both(monkeypatch):
    from hst.path.gates.firewall import _apply_firewall

    _both_models(monkeypatch, _accept_all("fwd:10"), _accept_all("zone:10"))
    trail, leg = path._Trail(), {}
    outcome = _apply_firewall(
        None,
        trail,
        leg,
        {"dev_uid": "dev:gw", "if_uid": "if:in"},
        "if:out",
        path._intervals(["10.20.1.50"]),
        path._intervals(["10.0.30.10"]),
        443,
        "tcp",
        "10.20.1.50",
        "eth2",
    )
    assert outcome == PERMIT
    rulebases = [h["uid"] for h in trail.hops if h["kind"] == "FwRulebase"]
    assert rulebases == ["vyos:gw:fw:ipv4-forward", "vyos:gw:fw:LAN-WAN"]
    assert [h["uid"] for h in trail.hops if h["kind"] == "FwRule"] == ["fwd:10", "zone:10"]
    assert leg["fw_uid"] == "vyos:gw:fw:ipv4-forward"
    assert leg["fw_uids"] == ["vyos:gw:fw:LAN-WAN", "vyos:gw:fw:ipv4-forward"]
    assert "LAN-WAN" in leg["firewall"] and "ipv4-forward" in leg["firewall"]
    assert "also crossed" in leg["firewall"]


def test_a_device_with_only_a_zone_pair_names_one_rulebase(monkeypatch):

    def read(s, q, **p):
        if "FROM_ZONE]->(src)" in q:
            return [_ZONE_MODEL]
        return _accept_all("zone:10") if "HAS_RULE" in q else []

    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", read)
    v = firewall._firewall_verdict(
        None,
        "dev:gw",
        "if:in",
        "if:out",
        path._intervals(["10.20.1.50"]),
        path._intervals(["10.0.30.10"]),
        443,
        "tcp",
        [],
    )
    assert classify_action(v["action"]) == PERMIT
    assert v["rb_uid"] == "vyos:gw:fw:LAN-WAN"
    assert "models" not in v


_LEGACY_MODEL = {
    "rb_uid": "unifi:gw:fwrs:LAN_IN",
    "rb_name": "LAN_IN",
    "vendor": "unifi",
    "af": None,
    "default_action": "drop",
    "default_action_unknown": False,
    "global_state_policy": None,
    "match_context": None,
    "chain": None,
    "approximate": False,
}


def _legacy_beside_zone(monkeypatch, legacy_rules, zone_rules):
    """A UniFi gateway as unifi.py writes one: zone policies and the classic
    `rest/firewallrule` rulesets, from the same payload. The classic ruleset
    is device-enforced, has no chain and carries no zone edges, so the
    device-wide candidate query accepts it."""

    def read(s, q, **p):
        if "FROM_ZONE]->(src)" in q:
            return [_ZONE_MODEL]
        if "coalesce(rb.chain, 'forward') = $chain" in q:
            return [_LEGACY_MODEL]
        if "HAS_RULE" in q:
            return legacy_rules if p.get("rb") == _LEGACY_MODEL["rb_uid"] else zone_rules
        return []

    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", read)


def test_a_chain_less_rulebase_beside_a_zone_policy_does_not_decide(monkeypatch):
    considered = []
    _legacy_beside_zone(monkeypatch, _drop_all("legacy:10"), _accept_all("zone:10"))
    v = firewall._firewall_verdict(
        None,
        "dev:gw",
        "if:in",
        "if:out",
        path._intervals(["10.20.1.50"]),
        path._intervals(["10.0.30.10"]),
        443,
        "tcp",
        considered,
    )
    assert classify_action(v["action"]) == PERMIT
    assert v["rb_uid"] == "vyos:gw:fw:LAN-WAN"
    assert v["rule_uid"] == "zone:10"
    assert "models" not in v
    assert considered == []


def test_a_chain_less_rulebase_decides_a_device_with_no_zone_policy(monkeypatch):

    def read(s, q, **p):
        if "FROM_ZONE]->(src)" in q:
            return []
        if "coalesce(rb.chain, 'forward') = $chain" in q:
            return [_LEGACY_MODEL]
        return _drop_all("legacy:10") if "HAS_RULE" in q else []

    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", read)
    v = firewall._firewall_verdict(
        None,
        "dev:gw",
        "if:in",
        "if:out",
        path._intervals(["10.20.1.50"]),
        path._intervals(["10.0.30.10"]),
        443,
        "tcp",
        [],
    )
    assert classify_action(v["action"]) == DENY
    assert v["rb_uid"] == "unifi:gw:fwrs:LAN_IN"
    assert v["rule_uid"] == "legacy:10"


def test_both_rulebase_queries_ask_for_the_default_action_marker(monkeypatch):
    queries = []

    def fake_read(session, query, **params):
        queries.append(query)
        return []

    monkeypatch.setattr(path, "_read", fake_read)
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    path._zone_pair_verdict(
        None, "if:in", "if:out", path._intervals(["10.0.0.5"]), path._intervals(["8.8.8.8"]), 443, "tcp", 4
    )
    assert _verdict() is None
    asked = [q for q in queries if "FROM_ZONE]->(src)" in q or "ENFORCES" in q]
    assert len(asked) == 3
    assert all("rb.default_action_unknown AS default_action_unknown" in q for q in asked)


# --- the addresses decide before an undecided service ------------------------------------

_UNDECIDED_SERVICE = "this rule's service is scoped to more than the query states"


def test_a_service_scoped_rule_whose_source_misses_is_skipped_by_a_protocol_less_query(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_cidrs=["192.168.7.0/24"],
            dst_any=True,
            protos=["tcp"],
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(proto=None)
    assert v["rule_uid"] == "cp:r2"
    assert classify_action(v["action"]) == PERMIT


def test_the_same_rule_is_undecided_once_its_addresses_do_match(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_cidrs=["10.0.0.0/24"],
            dst_any=True,
            protos=["tcp"],
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(proto=None)
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == _NO_PROTO


def test_an_undecided_service_never_leaves_the_reason_empty(graph):
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            svc_obj_count=1,
            protos=["tcp"],
            ports=[0],
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(port=None)
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == _UNDECIDED_SERVICE


def test_a_service_both_undecided_and_opaque_keeps_the_collectors_reason(graph):
    """The two are not alternatives: the query carries no protocol AND a member
    is one the collector could not map, so the note says both."""
    graph["rules"] = [
        _rule(
            uid="cp:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            svc_obj_count=1,
            protos=["tcp"],
            ports=["443"],
            svc_opaque=True,
            svc_opaque_reasons=["unsupported checkpoint service kind: service-other"],
        ),
        _rule(uid="cp:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(proto=None)
    assert v["rule_uid"] == "cp:r1"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == f"{_NO_PROTO}; unsupported checkpoint service kind: service-other"


# --- a zone that never recorded its default action ---------------------------------------


def test_a_zone_with_no_recorded_default_is_indeterminate_at_the_fall_through(monkeypatch):
    row = {
        "rb_uid": "vyos:gw:fw:GUEST-WAN",
        "rb_name": "GUEST-WAN",
        "af": 4,
        "default_action": None,
        "default_action_unknown": False,
        "src_zone": "GUEST",
        "dst_zone": "WAN",
        "zone_default": None,
        "zone_default_unknown": True,
    }
    rules = [_rule(uid="z:r1", pos=1, action="accept", src_cidrs=["192.168.0.0/24"], dst_any=True)]

    def read(s, q, **p):
        if "FROM_ZONE" in q:
            return [row]
        return rules if "HAS_RULE" in q else []

    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", read)
    src, dst = path._intervals(["192.168.110.53"]), path._intervals(["8.8.8.8"])
    v = path._zone_pair_verdict(None, "if:in", "if:out", src, dst, 443, "tcp", 4)
    assert v["by"] == "default-action"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == _UNSTATED_DEFAULT


def test_a_ruleset_stating_no_default_is_undecided_whatever_its_zone_states(monkeypatch):
    row = {
        "rb_uid": "unifi:s:fw:zone:lan:wan",
        "rb_name": "LAN-WAN",
        "af": None,
        "default_action": None,
        "default_action_unknown": None,
        "src_zone": "LAN",
        "dst_zone": "WAN",
        "zone_default": "drop",
        "zone_default_unknown": None,
    }
    rules = [_rule(uid="z:r1", pos=1, action="accept", src_cidrs=["192.168.0.0/24"], dst_any=True)]

    def read(s, q, **p):
        if "FROM_ZONE" in q:
            return [row]
        return rules if "HAS_RULE" in q else []

    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", read)
    src, dst = path._intervals(["10.1.1.1"]), path._intervals(["8.8.8.8"])
    v = path._zone_pair_verdict(None, "if:in", "if:out", src, dst, 443, "tcp", 4)
    assert v["by"] == "default-action"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == _UNSTATED_DEFAULT


def test_an_unbound_pair_with_no_recorded_destination_default_is_indeterminate(monkeypatch):
    """The same reading where no ruleset binds the pair at all: the destination
    zone's default-action is the whole answer there, and an unrecorded one
    cannot stand in for a drop."""
    _zones(
        monkeypatch,
        {
            "if:in": {"name": "LAN", "default_action": None},
            "if:out": {"name": "WAN", "default_action": None, "default_action_unknown": True},
        },
    )
    src, dst = path._intervals(["10.0.0.5"]), path._intervals(["8.8.8.8"])
    v = path._zone_pair_verdict(None, "if:in", "if:out", src, dst, 443, "tcp", 4)
    assert v["by"] == "default-action"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == _UNKNOWN_DEFAULT


# --- VyOS rule semantics: connection state, interface scope, port and protocol specs ---


def _names(graph, in_name="eth1", out_name="eth2.30"):
    graph["names"] = [{"uid": "if:in", "name": in_name}, {"uid": "if:out", "name": out_name}]


def test_a_rule_scoped_away_from_new_connections_is_skipped_not_applied(graph):
    graph["rules"] = [
        _rule(
            uid="fw:r1",
            pos=1,
            action="accept",
            src_any=True,
            dst_any=True,
            svc_any=True,
            states=["established", "related"],
        ),
        _rule(uid="fw:r2", pos=2, action="drop", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "fw:r2" and classify_action(v["action"]) == DENY
    assert v["state_skips"] == [{"pos": 1, "states": ["established", "related"]}]


def test_a_rule_that_includes_new_state_matches(graph):
    graph["rules"] = [
        _rule(uid="fw:r1", pos=1, action="accept", src_any=True, dst_any=True, svc_any=True, states=["new"])
    ]
    v = _verdict()
    assert v["rule_uid"] == "fw:r1" and classify_action(v["action"]) == PERMIT
    assert v["state_skips"] == []


def test_an_invalid_only_rule_is_skipped_and_the_default_action_decides(graph):
    graph["rules"] = [
        _rule(
            uid="fw:r1", pos=1, action="accept", src_any=True, dst_any=True, svc_any=True, states=["invalid"]
        )
    ]
    v = _verdict()
    assert v["by"] == "default-action" and classify_action(v["action"]) == DENY
    assert v["state_skips"] == [{"pos": 1, "states": ["invalid"]}]


def test_an_unreadable_state_clause_leaves_the_rule_undecided(graph):
    """The collector could not read the clause, so the rule can be neither
    applied nor skipped."""
    graph["rules"] = [
        _rule(
            uid="fw:r1",
            pos=1,
            action="accept",
            src_any=True,
            dst_any=True,
            svc_any=True,
            states_opaque=True,
            states_opaque_reason="connection state 'established' carries an unreadable value",
        )
    ]
    v = _verdict()
    assert classify_action(v["action"]) == INDETERMINATE
    assert "unreadable value" in v["indeterminate_reason"]


def test_an_unreadable_state_clause_on_a_rule_the_addresses_plainly_miss_is_skipped(graph):
    graph["rules"] = [
        _rule(
            uid="fw:r1",
            pos=1,
            action="accept",
            src_cidrs=["192.168.0.0/24"],
            dst_any=True,
            svc_any=True,
            states_opaque=True,
            states_opaque_reason="connection state 'established' carries an unreadable value",
        ),
        _rule(uid="fw:r2", pos=2, action="drop", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "fw:r2"
    assert classify_action(v["action"]) == DENY


def test_the_state_skip_is_a_leg_note_not_a_warning(graph):
    from hst.path.gates.firewall import _apply_firewall

    graph["rules"] = [
        _rule(
            uid="fw:r1",
            pos=1,
            action="accept",
            src_any=True,
            dst_any=True,
            svc_any=True,
            states=["established", "related"],
        ),
        _rule(uid="fw:r2", pos=2, action="drop", src_any=True, dst_any=True, svc_any=True),
    ]
    trail, leg = path._Trail(), {}
    outcome = _apply_firewall(
        None,
        trail,
        leg,
        {"dev_uid": "dev:fw1", "if_uid": "if:in"},
        "if:out",
        path._intervals(["10.0.0.0/24"]),
        path._intervals(["10.9.9.0/24"]),
        443,
        "tcp",
        "10.0.0.0/24",
        "eth0",
    )
    assert outcome == DENY
    assert leg.get("indeterminate") is not True
    notes = " ".join(trail.notes)
    assert "rule 1 is scoped to connection state established/related" in notes
    assert "new connection" in notes
    assert not [w for w in trail.warnings if "connection state" in w]


def test_the_global_state_policy_is_reported_on_the_leg(graph):
    """The device-wide state policy decides established and related traffic
    ahead of every ruleset; the leg says so, since the rulesets it walks judge
    the new flow only."""
    from hst.path.gates.firewall import _apply_firewall

    graph["rb"] = {
        **RB,
        "vendor": "vyos",
        "global_state_policy": ["established=accept", "invalid=drop", "related=accept"],
    }
    graph["rules"] = [_rule(uid="fw:r1", pos=1, action="accept", src_any=True, dst_any=True, svc_any=True)]
    trail, leg = path._Trail(), {}
    _apply_firewall(
        None,
        trail,
        leg,
        {"dev_uid": "dev:fw1", "if_uid": "if:in"},
        "if:out",
        path._intervals(["10.0.0.0/24"]),
        path._intervals(["10.9.9.0/24"]),
        443,
        "tcp",
        "10.0.0.0/24",
        "eth0",
    )
    notes = " ".join(trail.notes)
    assert "global state policy (established=accept, invalid=drop, related=accept)" in notes
    assert not trail.warnings


def test_a_vyos_device_with_a_known_state_policy_admits_the_reply_from_session_state(monkeypatch):
    """A device whose own global_state_policy was collected, crossed by a
    confirmed-permit forward leg, admits the reply with no rule match at
    all: the state policy is the evidence, not a rule the reply's own
    (reversed) tuple happens to hit."""
    from hst.path.gates.firewall import _apply_firewall_reply

    policy = ["established=accept", "related=accept"]

    def fake_read_one(session, query, **params):
        if "global_state_policy IS NOT NULL" in query:
            return {"global_state_policy": policy}
        return None

    def fake_read(session, query, **params):
        return []

    monkeypatch.setattr(path, "_read_one", fake_read_one)
    monkeypatch.setattr(path, "_read", fake_read)

    trail = path._Trail()
    trail.device_gate_state["dev:fw1"] = {"policy": policy, "permit": True}
    leg: dict = {}
    outcome = _apply_firewall_reply(
        None,
        trail,
        leg,
        {"dev_uid": "dev:fw1", "dev_name": "fw1", "if_uid": "if:in"},
        "if:out",
        path._intervals(["203.0.113.10"]),
        path._intervals(["10.0.0.5"]),
        None,
        None,
        "203.0.113.10",
        "eth0",
    )
    assert outcome == PERMIT
    assert leg.get("indeterminate") is not True
    assert "admitted from session state" in leg["firewall"]
    notes = " ".join(trail.notes)
    assert "fw1's global state policy (established=accept, related=accept) already covers" in notes
    assert "confirmed permit" in notes
    assert not trail.warnings


def test_a_state_policy_with_no_confirmed_forward_permit_does_not_admit_from_session_state(monkeypatch):
    """A known state policy alone is not evidence: the forward leg through
    this device must have been confirmed permitted, or the reply falls
    through to ordinary rule evaluation like any other unconfirmed hop."""
    from hst.path.gates.firewall import _apply_firewall_reply

    def fake_read_one(session, query, **params):
        if "global_state_policy IS NOT NULL" in query:
            return {"global_state_policy": ["established=accept"]}
        return None

    def fake_read(session, query, **params):
        if "HAS_RULE" in query:
            return [_rule(src_any=True, dst_any=True, svc_any=True, action="accept")]
        if "ENFORCES" in query:
            return [RB]
        return []

    monkeypatch.setattr(path, "_read_one", fake_read_one)
    monkeypatch.setattr(path, "_read", fake_read)

    trail = path._Trail()
    leg: dict = {}
    outcome = _apply_firewall_reply(
        None,
        trail,
        leg,
        {"dev_uid": "dev:fw1", "dev_name": "fw1", "if_uid": "if:in"},
        "if:out",
        path._intervals(["203.0.113.10"]),
        path._intervals(["10.0.0.5"]),
        None,
        None,
        "203.0.113.10",
        "eth0",
    )
    assert outcome == PERMIT
    assert "firewall" in leg
    assert "admitted from session state" not in leg["firewall"]


def test_a_wildcard_interface_scope_matches_by_prefix(graph):
    _names(graph)
    graph["rules"] = [
        _rule(uid="fw:r1", pos=1, action="drop", out_if="eth2*", src_any=True, dst_any=True, svc_any=True)
    ]
    v = _verdict()
    assert v["rule_uid"] == "fw:r1" and classify_action(v["action"]) == DENY


def test_a_wildcard_interface_scope_misses_another_interface(graph):
    _names(graph, out_name="eth3")
    graph["rules"] = [
        _rule(uid="fw:r1", pos=1, action="drop", out_if="eth2*", src_any=True, dst_any=True, svc_any=True)
    ]
    assert _verdict()["by"] == "default-action"


def test_a_negated_interface_scope_governs_every_other_interface(graph):
    _names(graph, in_name="eth1")
    graph["rules"] = [
        _rule(uid="fw:r1", pos=1, action="drop", in_if="!eth0", src_any=True, dst_any=True, svc_any=True)
    ]
    assert _verdict()["rule_uid"] == "fw:r1"
    _names(graph, in_name="eth0")
    assert _verdict()["by"] == "default-action"


def test_a_combined_negation_and_wildcard_scope_is_read_as_one_pattern(graph):
    _names(graph, in_name="eth2.30")
    graph["rules"] = [
        _rule(uid="fw:r1", pos=1, action="drop", in_if="!eth2*", src_any=True, dst_any=True, svc_any=True)
    ]
    assert _verdict()["by"] == "default-action"
    _names(graph, in_name="eth1")
    assert _verdict()["rule_uid"] == "fw:r1"


def test_an_interface_group_scope_leaves_the_rule_undecided(graph):
    """Interface-group membership is not collected anywhere, so the rule can
    neither be confirmed to govern this leg nor skipped past."""
    _names(graph)
    graph["rules"] = [
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            out_if_group="WAN-GROUP",
            src_any=True,
            dst_any=True,
            svc_any=True,
        )
    ]
    v = _verdict()
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == "the rule's interface-group scope is not collected"


def test_a_negated_interface_group_scope_is_undecided_for_the_same_reason(graph):
    _names(graph)
    graph["rules"] = [
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            in_if_group="!LAN-GROUP",
            src_any=True,
            dst_any=True,
            svc_any=True,
        )
    ]
    v = _verdict()
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == "the rule's interface-group scope is not collected"


def test_a_resolved_named_port_matches_the_flows_numeric_port(graph):
    graph["rules"] = [
        _rule(uid="fw:r1", pos=1, action="drop", src_any=True, dst_any=True, protos=["tcp"], ports=[["22"]])
    ]
    assert classify_action(_verdict(port=22)["action"]) == DENY
    assert _verdict(port=80)["by"] == "default-action"


def test_a_service_name_the_collector_could_not_resolve_leaves_the_rule_undecided(graph):
    graph["rules"] = [
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            protos=["tcp"],
            ports=[["my-custom-app"]],
            svc_obj_count=1,
            svc_opaque=True,
            svc_opaque_reasons=["unknown service name: 'my-custom-app'"],
        )
    ]
    v = _verdict(port=22)
    assert classify_action(v["action"]) == INDETERMINATE
    assert "my-custom-app" in v["indeterminate_reason"]


def test_a_negated_protocol_rule_governs_every_other_protocol(graph):
    graph["rules"] = [_rule(uid="fw:r1", pos=1, action="drop", src_any=True, dst_any=True, protos=["!tcp"])]
    assert classify_action(_verdict(proto="udp")["action"]) == DENY
    assert _verdict(proto="tcp")["by"] == "default-action"


def test_a_negated_compound_protocol_rule_excludes_both_members(graph):
    graph["rules"] = [
        _rule(uid="fw:r1", pos=1, action="drop", src_any=True, dst_any=True, protos=["!tcp_udp"])
    ]
    assert classify_action(_verdict(proto="icmp")["action"]) == DENY
    assert _verdict(proto="tcp")["by"] == "default-action"
    assert _verdict(proto="udp")["by"] == "default-action"


# --- a source port is a dimension of the rule, not an unknown member -----------


def test_a_source_port_scoped_rule_that_otherwise_matches_is_undecided(graph):
    graph["rules"] = [
        _rule(
            uid="fw:r1",
            pos=1,
            action="accept",
            src_any=True,
            dst_any=True,
            protos=["udp"],
            ports=[["546"]],
            svc_obj_count=1,
            svc_src_port=True,
        )
    ]
    v = _verdict(port=546, proto="udp")
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == "the rule matches on a source port the flow does not carry"


def test_a_source_port_scoped_rule_whose_other_dimensions_miss_is_skipped(graph):
    graph["rules"] = [
        _rule(
            uid="fw:r1",
            pos=1,
            action="accept",
            src_any=True,
            dst_any=True,
            protos=["udp"],
            ports=[["546"]],
            svc_obj_count=1,
            svc_src_port=True,
        ),
        _rule(uid="fw:r2", pos=2, action="drop", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(port=80, proto="tcp")
    assert v["rule_uid"] == "fw:r2" and classify_action(v["action"]) == DENY


def test_a_rule_scoped_to_nothing_but_a_source_port_is_undecided(graph):
    """The rule constrains one dimension and it is the one the tuple has not
    got, so there is nothing here to decide either way."""
    graph["rules"] = [
        _rule(
            uid="fw:r1",
            pos=1,
            action="accept",
            src_any=True,
            dst_any=True,
            svc_obj_count=1,
            svc_src_port=True,
        )
    ]
    v = _verdict()
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == "the rule matches on a source port the flow does not carry"


# --- the interface-group scope is read after the rule otherwise applies ---


def test_a_group_scoped_rule_whose_addresses_miss_is_skipped_not_undecided(graph):
    _names(graph)
    graph["rules"] = [
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            out_if_group="WAN-GROUP",
            src_any=True,
            dst_cidrs=["10.8.8.0/24"],
            dst_obj_count=1,
            svc_any=True,
        ),
        _rule(uid="fw:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict()
    assert v["rule_uid"] == "fw:r2" and classify_action(v["action"]) == PERMIT


def test_a_group_scoped_rule_whose_service_misses_is_skipped_too(graph):
    _names(graph)
    graph["rules"] = [
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            in_if_group="LAN-GROUP",
            src_any=True,
            dst_any=True,
            protos=["tcp"],
            ports=[["22"]],
            svc_obj_count=1,
        ),
        _rule(uid="fw:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(port=443, proto="tcp")
    assert v["rule_uid"] == "fw:r2" and classify_action(v["action"]) == PERMIT


def test_a_group_scoped_rule_that_otherwise_matches_is_undecided(graph):
    """The other half of the same order: nothing collects group membership, so
    a rule the flow otherwise reaches is neither applied nor passed over."""
    _names(graph)
    graph["rules"] = [
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            out_if_group="WAN-GROUP",
            src_any=True,
            dst_any=True,
            protos=["tcp"],
            ports=[["443"]],
            svc_obj_count=1,
        ),
        _rule(uid="fw:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
    ]
    v = _verdict(port=443, proto="tcp")
    assert v["rule_uid"] == "fw:r1"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == "the rule's interface-group scope is not collected"


# --- collected rows, straight from the normalizer -----------


def _collector_rows(batch, rb_uid: str):
    """(rulebase row, rule rows) for one collected rulebase, as the gate reads them.

    The two queries in the gate name their columns off FwRulebase, FwRule and
    SvcObject properties; this reads the same properties off a normalized batch,
    so a collector shape reaches the gate here without a database in between.
    Address objects are not projected: a rule with an address side needs the
    NetObject closure the Cypher walks, and `tests/test_integration_db.py` is
    where that is checked against real Cypher.
    """
    props = {(n.label, n.uid): dict(n.props) for n in batch.nodes}
    rows = []
    for rel in batch.rels:
        if rel.rel_type != "HAS_RULE" or rel.start_uid != rb_uid:
            continue
        p = props[("FwRule", rel.end_uid)]
        if not p.get("enabled", True):
            continue
        svcs = [
            props[("SvcObject", s.end_uid)]
            for s in batch.rels
            if s.rel_type == "SVC" and s.start_uid == rel.end_uid
        ]
        rows.append(
            _rule(
                uid=rel.end_uid,
                pos=p["position"],
                action=p.get("action"),
                name=p.get("name"),
                out_if=p.get("out_interface"),
                in_if=p.get("in_interface"),
                out_if_group=p.get("out_interface_group"),
                in_if_group=p.get("in_interface_group"),
                states=p.get("states", []),
                states_opaque=p.get("states_opaque", False),
                states_opaque_reason=p.get("states_opaque_reason"),
                src_any=p.get("src_any", False),
                dst_any=p.get("dst_any", False),
                protos=[s.get("proto") for s in svcs],
                ports=[s.get("ports") for s in svcs],
                svc_obj_count=len(svcs),
                svc_opaque=any(s.get("opaque") for s in svcs),
                svc_opaque_reasons=[s["opaque_reason"] for s in svcs if s.get("opaque_reason")],
                svc_src_port=any(s.get("src_port") for s in svcs),
            )
        )
    rb = props[("FwRulebase", rb_uid)]
    rb_row = {
        "rb_uid": rb_uid,
        "rb_name": rb.get("name"),
        "vendor": rb.get("vendor"),
        "af": rb.get("af"),
        "default_action": rb.get("default_action"),
        "default_action_unknown": rb.get("default_action_unknown"),
        "global_state_policy": rb.get("global_state_policy"),
        "approximate": False,
    }
    return rb_row, sorted(rows, key=lambda r: r["pos"])


def _vyos_batch(firewall: dict):
    from hst.collectors.vyos import normalize_vyos

    raw = {
        "config": {
            "system": {"host-name": "gw"},
            "interfaces": {"ethernet": {"eth0": {"address": ["10.0.0.1/24"]}}},
            "firewall": firewall,
        },
        "version_text": "Version:          VyOS 1.4.0\nHardware S/N:     0000",
        "links": [],
    }
    return normalize_vyos(raw, l3dom="dc1")


def test_a_collected_chain_without_a_default_action_falls_through_to_indeterminate(graph):
    batch = _vyos_batch(
        {"ipv4": {"forward": {"filter": {"rule": {"10": {"action": "accept", "protocol": "tcp"}}}}}}
    )
    rb, rules = _collector_rows(batch, "vyos:gw:fw:ipv4-forward")
    graph["rb"], graph["rules"] = rb, rules
    assert rb["default_action_unknown"] is True
    v = _verdict(proto="udp")
    assert v["by"] == "default-action"
    assert classify_action(v["action"]) == INDETERMINATE
    assert v["indeterminate_reason"] == _UNKNOWN_DEFAULT


def test_a_collected_rule_naming_no_connection_state_governs_the_flow(graph):
    """The collector writes an explicit empty states list so a removed state
    clause overwrites the one already on the node. Empty has to read at the gate
    as no constraint, not as a state set the traced flow lacks."""
    batch = _vyos_batch(
        {
            "ipv4": {
                "forward": {
                    "filter": {
                        "default-action": "drop",
                        "rule": {"10": {"action": "accept", "protocol": "tcp"}},
                    }
                }
            }
        }
    )
    rb, rules = _collector_rows(batch, "vyos:gw:fw:ipv4-forward")
    assert rules[0]["states"] == []
    assert rules[0]["in_if_group"] == "" and rules[0]["out_if_group"] == ""
    graph["rb"], graph["rules"] = rb, rules
    v = _verdict()
    assert v["rule_uid"] == "vyos:gw:fw:ipv4-forward:10"
    assert classify_action(v["action"]) == PERMIT
    assert v["state_skips"] == []


def test_the_candidates_query_orders_the_whole_union_not_one_branch():
    from hst.path.gates.firewall import _RULEBASE_CANDIDATES

    body = _RULEBASE_CANDIDATES.strip()
    assert body.startswith("CALL {")
    assert body.endswith("ORDER BY rb_name")
    # exactly one RETURN outside the subquery, and it is the one that is sorted
    outer = body[body.rindex("}") + 1 :]
    assert outer.count("RETURN") == 1
    assert "UNION" not in outer


class TestAsPortsetAsProtoset:
    @pytest.mark.parametrize("port", [443, "443"])
    def test_a_scalar_port_round_trips_to_the_one_element_interval(self, port):
        ivals, is_range = _as_portset(port)
        assert is_range is False
        assert ivals == [(0, 443, 443)]

    def test_a_none_port_states_nothing(self):
        assert _as_portset(None) == (None, False)

    @pytest.mark.parametrize(
        "port", ["any", "0-65535", "80,443", "1-1024", [443, 8443], frozenset({80, 443})]
    )
    def test_a_range_port_is_recognised_as_a_range(self, port):
        _, is_range = _as_portset(port)
        assert is_range is True

    def test_a_frozenset_port_is_a_range_the_same_way_a_frozenset_protocol_is(self):
        ivals, is_range = _as_portset(frozenset({80, 443}))
        assert is_range is True
        assert ivals == [(0, 80, 80), (0, 443, 443)]

    @pytest.mark.parametrize("proto", ["tcp", "udp", "icmp"])
    def test_a_scalar_protocol_name_round_trips_to_the_one_element_set(self, proto):
        proto_set, is_range = _as_protoset(proto)
        assert is_range is False
        assert proto_set == _protoset([proto])

    def test_a_none_protocol_states_nothing(self):
        assert _as_protoset(None) == (None, False)

    @pytest.mark.parametrize("proto", [["tcp", "udp"], frozenset({6, 17})])
    def test_a_range_protocol_is_recognised_as_a_range(self, proto):
        _, is_range = _as_protoset(proto)
        assert is_range is True

    @pytest.mark.parametrize("proto", ["any", "all", "tcp_udp", "ipsec", "ip"])
    def test_a_protocol_keyword_stays_a_scalar_value(self, proto):
        assert firewall._states_a_range(None, proto) is False

    def test_a_hyphenated_protocol_name_is_not_mistaken_for_a_port_range(self):
        proto_set, is_range = _as_protoset("ipv6-icmp")
        assert is_range is False
        assert proto_set == frozenset({58})

    def test_a_one_element_list_is_the_scalar_it_holds(self):
        """A one-element set, spelled as a list: not a range on
        either side, so it takes the same point path the bare scalar does."""
        assert _as_portset([443]) == ([(0, 443, 443)], False)
        assert _as_protoset(["tcp"]) == (frozenset({6}), False)

    def test_an_empty_list_states_nothing_on_either_side(self):
        assert _as_portset([]) == (None, False)
        assert _as_protoset([]) == (None, False)


_R_SRC = path._intervals(["10.0.0.0/24"])
_R_DST = path._intervals(["10.9.9.0/24"])


def _regions(rules, port, proto):
    return _first_match(rules, None, None, _R_SRC, _R_DST, port, proto)


class TestFirstMatchRegions:
    def test_a_port_range_query_against_a_port_scoped_rule_splits_into_two_regions(self):
        rules = [
            _rule(
                uid="fw:r1", pos=1, action="drop", src_any=True, dst_any=True, protos=["tcp"], ports=["443"]
            ),
            _rule(uid="fw:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
        ]
        regions = _regions(rules, "440-450", "tcp")
        assert len(regions) == 2
        matched = next(reg for reg in regions if reg[4] == [(0, 443, 443)])
        r, _src_hit, _dst_hit, proto_sub, _port_sub = matched
        assert classify_action(r["action"]) == DENY
        assert r["uid"] == "fw:r1"
        assert proto_sub == frozenset({6})
        remainder = next(reg for reg in regions if reg is not matched)
        r2, _, _, _, port_sub2 = remainder
        assert classify_action(r2["action"]) == PERMIT
        assert r2["uid"] == "fw:r2"
        assert port_sub2 == [(0, 440, 442), (0, 444, 450)]

    def test_a_two_protocol_query_against_a_rule_scoped_to_one_protocol_splits(self):
        rules = [
            _rule(uid="fw:r1", pos=1, action="drop", src_any=True, dst_any=True, protos=["tcp"]),
            _rule(uid="fw:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
        ]
        regions = _regions(rules, 443, ["tcp", "udp"])
        assert len(regions) == 2
        tcp_r, *_ = next(reg for reg in regions if reg[3] == frozenset({6}))
        udp_r, *_ = next(reg for reg in regions if reg[3] == frozenset({17}))
        assert classify_action(tcp_r["action"]) == DENY
        assert tcp_r["uid"] == "fw:r1"
        assert classify_action(udp_r["action"]) == PERMIT
        assert udp_r["uid"] == "fw:r2"

    def test_svc_negate_stays_per_region(self):
        rules = [
            _rule(
                uid="fw:r1",
                pos=1,
                action="drop",
                src_any=True,
                dst_any=True,
                protos=["tcp"],
                svc_negate=True,
            ),
            _rule(uid="fw:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
        ]
        regions = _regions(rules, None, ["tcp", "udp"])
        assert len(regions) == 2
        tcp_reg = next(reg for reg in regions if reg[3] == frozenset({6}))
        udp_reg = next(reg for reg in regions if reg[3] == frozenset({17}))
        assert classify_action(udp_reg[0]["action"]) == DENY
        assert udp_reg[0]["uid"] == "fw:r1"
        assert classify_action(tcp_reg[0]["action"]) == PERMIT
        assert tcp_reg[0]["uid"] == "fw:r2"
        assert tcp_reg[4] is None
        assert udp_reg[4] is None

    def test_an_opaque_member_leaves_only_its_own_region_undecided(self):
        rules = [
            _rule(
                uid="fw:r1",
                pos=1,
                action="drop",
                src_any=True,
                dst_any=True,
                protos=["udp", "tcp"],
                ports=["53", ["my-custom-app"]],
                svc_opaque=True,
                svc_opaque_reasons=["unknown service name: 'my-custom-app'"],
            )
        ]
        regions = _regions(rules, 53, ["tcp", "udp"])
        assert len(regions) == 2
        udp_reg = next(reg for reg in regions if reg[3] == frozenset({17}))
        tcp_reg = next(reg for reg in regions if reg[3] == frozenset({6}))
        assert classify_action(udp_reg[0]["action"]) == DENY
        assert udp_reg[0]["uid"] == "fw:r1"
        assert classify_action(tcp_reg[0]["action"]) == INDETERMINATE
        assert "my-custom-app" in tcp_reg[0]["indeterminate_reason"]

    def test_an_address_only_rule_matches_every_region_of_a_ranged_query(self):
        rules = [_rule(uid="fw:r1", pos=1, action="drop", src_any=True, dst_any=True)]

        regions = _regions(rules, 443, ["tcp", "udp"])
        assert len(regions) == 1
        r, _, _, proto_sub, _ = regions[0]
        assert classify_action(r["action"]) == DENY
        assert proto_sub == frozenset({6, 17})

        regions2 = _regions(rules, "440-450", None)
        assert len(regions2) == 1
        r2, _, _, proto_sub2, port_sub2 = regions2[0]
        assert classify_action(r2["action"]) == DENY
        assert proto_sub2 is None
        assert port_sub2 == [(0, 440, 450)]


class TestVerdictBuildersAcceptARangedQuery:
    def test_a_device_rulebase_ranged_port_query_returns_a_list_of_regions(self, graph):
        graph["rules"] = [
            _rule(
                uid="cp:r1", pos=1, action="accept", src_any=True, dst_any=True, protos=["tcp"], ports=["443"]
            )
        ]
        v = _verdict(port="1-1024")
        assert isinstance(v, list)
        assert len(v) == 2
        matched = next(d for d in v if d["port_subset"] == [(0, 443, 443)])
        assert classify_action(matched["action"]) == PERMIT
        assert matched["proto_subset"] == frozenset({6})
        remainder = next(d for d in v if d is not matched)
        assert remainder["by"] == "default-action"
        assert classify_action(remainder["action"]) == DENY
        assert remainder["port_subset"] == [(0, 1, 442), (0, 444, 1024)]

    def test_a_zone_pair_ranged_port_query_returns_a_list_of_regions(self, monkeypatch):
        row = {
            "rb_uid": "vyos:gw:fw:GUEST-WAN",
            "rb_name": "GUEST-WAN",
            "af": 4,
            "default_action": "drop",
            "src_zone": "GUEST",
            "dst_zone": "WAN",
            "zone_default": "drop",
        }
        rules = [
            _rule(
                uid="vyos:r1",
                pos=1,
                action="accept",
                src_any=True,
                dst_any=True,
                protos=["tcp"],
                ports=["443"],
            )
        ]

        def fake_read(s, q, **p):
            if "FROM_ZONE" in q:
                return [row]
            if "HAS_RULE" in q:
                return rules
            return []

        monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
        monkeypatch.setattr(path, "_read", fake_read)
        src, dst = path._intervals(["10.0.0.5"]), path._intervals(["8.8.8.8"])
        v = path._zone_pair_verdict(None, "if:in", "if:out", src, dst, "1-1024", "tcp", 4)
        assert isinstance(v, list)
        assert len(v) == 2
        matched = next(d for d in v if d["port_subset"] == [(0, 443, 443)])
        assert classify_action(matched["action"]) == PERMIT
        assert matched["rule_uid"] == "vyos:r1"
        remainder = next(d for d in v if d is not matched)
        assert classify_action(remainder["action"]) == DENY
        assert remainder["by"] == "default-action"
        assert remainder["port_subset"] == [(0, 1, 442), (0, 444, 1024)]


class TestAScalarQueryNeverParsesOnTheWayIn:
    @pytest.mark.parametrize("proto", ["ipsec", "ip"])
    def test_a_protocol_name_outside_the_number_table_matches(self, proto):
        rules = [
            _rule(uid="fw:r1", pos=1, action="drop", src_any=True, dst_any=True, protos=[proto]),
            _rule(uid="fw:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
        ]
        m = _first_match(rules, None, None, _R_SRC, _R_DST, 443, proto)
        assert m == _first_match_point(rules, None, None, _R_SRC, _R_DST, 443, proto)
        assert m[0]["uid"] == "fw:r1"
        assert classify_action(m[0]["action"]) == DENY

    @pytest.mark.parametrize("proto", ["any", "tcp_udp"])
    def test_a_protocol_keyword_answers_as_the_point_path_answers_it(self, proto):
        rules = [
            _rule(
                uid="fw:r1", pos=1, action="drop", src_any=True, dst_any=True, protos=["tcp"], ports=["443"]
            ),
            _rule(uid="fw:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
        ]
        m = _first_match(rules, None, None, _R_SRC, _R_DST, 443, proto)
        assert m == _first_match_point(rules, None, None, _R_SRC, _R_DST, 443, proto)
        assert m[0]["uid"] == "fw:r2"

    def test_a_one_element_list_takes_the_point_path(self):
        """A one-element set spelled as a list is the scalar it
        holds, so it returns the point path's own tuple and not a region."""
        rules = [_rule(uid="fw:r1", pos=1, action="drop", src_any=True, dst_any=True, svc_any=True)]
        m = _first_match(rules, None, None, _R_SRC, _R_DST, [443], ["tcp"])
        assert m == _first_match_point(rules, None, None, _R_SRC, _R_DST, 443, "tcp")

    def test_a_bare_protocol_number_matches_a_rule_spelled_by_name(self):
        rules = [
            _rule(
                uid="fw:r1", pos=1, action="accept", src_any=True, dst_any=True, protos=["tcp"], ports=["443"]
            ),
            _rule(uid="fw:r2", pos=2, action="drop", src_any=True, dst_any=True, svc_any=True),
        ]
        m = _first_match(rules, None, None, _R_SRC, _R_DST, 443, "6")
        assert m == _first_match_point(rules, None, None, _R_SRC, _R_DST, 443, "6")
        assert m[0]["uid"] == "fw:r1"
        assert classify_action(m[0]["action"]) == PERMIT


class TestARangedQueryIsRefusedWhereALegExpectsOneVerdict:
    @pytest.mark.parametrize("port", ["440-450", "80,443", [80, 443]])
    def test_a_ranged_port_is_refused(self, port):
        with pytest.raises(ValueError, match="not supported on this path"):
            firewall._refuse_ranged_query(port, "tcp")

    def test_a_ranged_protocol_is_refused(self):
        with pytest.raises(ValueError, match="not supported on this path"):
            firewall._refuse_ranged_query(443, ["tcp", "udp"])

    def test_a_scalar_query_is_not_refused(self):
        # the same check with a scalar port and a protocol name the number
        # table does not carry: nothing to refuse, and the trace runs on
        assert firewall._refuse_ranged_query(443, "ipsec") is None
        assert firewall._refuse_ranged_query(None, None) is None

    def test_the_leg_level_read_itself_refuses_a_ranged_port(self):
        """The guard is reached through the call site, not only on its own:
        `_apply_firewall` mutates one leg from one verdict, so a range has to
        be refused there before any rulebase is read."""
        gw = {"dev_uid": "dev:r1", "dev_name": "r1", "if_uid": "if:eth1"}
        with pytest.raises(ValueError, match="not supported on this path"):
            firewall._apply_firewall(
                None, path._Trail(), {}, gw, "if:eth0", [], [], "440-450", "tcp", "10.0.0.5", "eth0"
            )

    def test_the_router_local_read_itself_refuses_a_ranged_protocol(self):
        """`_firewall_verdict_local` reads one verdict for the input or output
        chain the same way, so it refuses the same query."""
        with pytest.raises(ValueError, match="not supported on this path"):
            firewall._firewall_verdict_local(None, "dev:r1", None, [], [], 443, ["tcp", "udp"])


# The rule shapes the point path answers on grounds other than a plain
# service match: an opaque or unreadable address side, a scope the collector
# could not read, a negated side, a dimension the query does not carry. Each
# list ends with an any/any accept, so a rule that does not govern the flow
# falls through to a verdict that differs from the first rule's.
def _shape(*head):
    return [*head, _rule(uid="fw:last", pos=9, action="accept", src_any=True, dst_any=True, svc_any=True)]


_RULE_SHAPES = {
    "plain any any": _shape(
        _rule(uid="fw:r1", pos=1, action="drop", src_any=True, dst_any=True, svc_any=True)
    ),
    "opaque source object": _shape(
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            src_obj_count=1,
            src_opaque=True,
            src_opaque_reasons=["group not modeled"],
            dst_any=True,
            protos=["tcp"],
            ports=["443"],
        )
    ),
    "unparsed cidrs": _shape(
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            src_cidrs=["not-an-address"],
            dst_any=True,
            protos=["tcp"],
            ports=["443"],
        )
    ),
    "address gap": _shape(
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            src_obj_count=1,
            dst_any=True,
            protos=["tcp"],
            ports=["443"],
        )
    ),
    "source port scope": _shape(
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            svc_obj_count=1,
            svc_src_port=True,
            protos=["tcp"],
            ports=["443"],
        )
    ),
    "unread state clause": _shape(
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            protos=["tcp"],
            ports=["443"],
            states_opaque=True,
            states_opaque_reason="the rule's state clause could not be read",
        )
    ),
    "interface group scope": _shape(
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            protos=["tcp"],
            ports=["443"],
            out_if_group="GROUP",
        )
    ),
    "negated source": _shape(
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            src_cidrs=["10.0.0.0/24"],
            src_obj_count=1,
            src_negate=True,
            dst_any=True,
            svc_any=True,
        )
    ),
    "negated service": _shape(
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            protos=["tcp"],
            ports=["443"],
            svc_negate=True,
        )
    ),
    "opaque service member": _shape(
        _rule(
            uid="fw:r1",
            pos=1,
            action="drop",
            src_any=True,
            dst_any=True,
            svc_obj_count=2,
            protos=["tcp"],
            ports=["443"],
            svc_opaque=True,
            svc_opaque_reasons=["unknown service name: 'my-app'"],
        )
    ),
    "services carrying nothing": _shape(
        _rule(uid="fw:r1", pos=1, action="drop", src_any=True, dst_any=True, svc_obj_count=1)
    ),
    "no service members": _shape(_rule(uid="fw:r1", pos=1, action="drop", src_any=True, dst_any=True)),
}

_QUERY_POINTS = [(443, "tcp"), (445, "tcp"), (53, "udp"), (443, None), (None, "tcp"), (None, None)]

_UNREADABLE_MEMBER_SHAPE = _shape(
    _rule(
        uid="fw:r1",
        pos=1,
        action="drop",
        src_any=True,
        dst_any=True,
        protos=["fooproto"],
        ports=["443"],
    )
)


class TestThePointAndRegionPathsAgreeOnEveryRuleShape:
    @pytest.mark.parametrize("shape", sorted(_RULE_SHAPES))
    @pytest.mark.parametrize(("port", "proto"), _QUERY_POINTS)
    def test_one_element_sets_reproduce_the_point_verdict(self, shape, port, proto):
        rules = _RULE_SHAPES[shape]
        point = _first_match_point(rules, None, None, _R_SRC, _R_DST, port, proto)
        proto_set = None if proto is None else _protoset([proto])
        port_ivals = None if port is None else _ports(port)
        regions = _first_match_regions(rules, None, None, _R_SRC, _R_DST, proto_set, port_ivals)

        assert len(regions) == 1
        rule, _src_hit, _dst_hit, proto_sub, port_sub = regions[0]
        assert proto_sub == proto_set
        assert port_sub == port_ivals
        if point is None:
            # no rule decided the flow: both paths hand the caller its own
            # default-action fallback
            assert rule is None
            return
        assert rule is not None
        assert rule["uid"] == point[0]["uid"]
        assert rule["action"] == point[0]["action"]
        assert rule.get("indeterminate_reason") == point[0].get("indeterminate_reason")

    def test_an_unreadable_member_protocol_is_undecided_on_both_paths(self):
        """A member's own protocol spec (`fooproto`) is a name
        `_protoset` cannot resolve. Neither path can tell whether it names
        the `tcp` flow's protocol, so neither skips the drop rule past to the
        trailing any/any accept: the point path's `_proto_matches` reads the
        member as undecided, and the region path's
        `_service_regions` cannot decide the member's protocol dimension, so
        both return `fw:r1` INDETERMINATE with the same reason."""
        rules = _UNREADABLE_MEMBER_SHAPE
        point = _first_match_point(rules, None, None, _R_SRC, _R_DST, 443, "tcp")
        assert point is not None
        assert point[0]["uid"] == "fw:r1"
        assert point[0]["action"] == INDETERMINATE
        assert point[0].get("indeterminate_reason") == firewall._UNDECIDED_SERVICE_REASON

        proto_set = _protoset(["tcp"])
        port_ivals = _ports(443)
        regions = _first_match_regions(rules, None, None, _R_SRC, _R_DST, proto_set, port_ivals)
        assert len(regions) == 1
        rule, _src_hit, _dst_hit, proto_sub, port_sub = regions[0]
        assert rule is not None
        assert rule["uid"] == "fw:r1"
        assert rule["action"] == INDETERMINATE
        assert rule.get("indeterminate_reason") == firewall._UNDECIDED_SERVICE_REASON
        assert proto_sub == proto_set
        assert port_sub == port_ivals


def _overlaps(a, b):
    return bool(_intersect(list(a), list(b)))


class TestTheServiceSideReturnsAPartition:
    _OVERLAPPING = _rule(
        uid="fw:r1",
        pos=1,
        action="drop",
        src_any=True,
        dst_any=True,
        protos=["tcp", "tcp"],
        ports=["443", "400-500"],
    )

    def test_no_port_is_claimed_by_two_members_of_one_rule(self):
        entries = firewall._service_split(self._OVERLAPPING, frozenset({6}), _ports("400-500"), False)
        seen: list[tuple[int, int, int]] = []
        for _kind, _action, _reason, _rp, rq in entries:
            assert rq is not None
            assert not _overlaps(seen, rq)
            seen.extend(rq)
        assert _merge(seen) == [(0, 400, 500)]

    def test_overlapping_members_come_back_as_one_region(self):
        regions = _regions([self._OVERLAPPING], "400-500", "tcp")
        assert len(regions) == 1
        rule, _src, _dst, _proto_sub, port_sub = regions[0]
        assert rule["uid"] == "fw:r1"
        assert port_sub == [(0, 400, 500)]

    def test_a_matched_region_keeps_an_unstated_protocol_unstated(self):
        """A member scoping only ports claims every protocol, which is the
        full range standing in for "matches regardless" and not a query that
        names all 256 of them."""
        rules = [_rule(uid="fw:r1", pos=1, action="drop", src_any=True, dst_any=True, ports=["443"])]
        regions = _regions(rules, "440-450", None)
        matched = next(reg for reg in regions if reg[4] == [(0, 443, 443)])
        assert matched[0]["uid"] == "fw:r1"
        assert matched[3] is None


class TestTheRegionCapAndMergeByOutcome:
    """The two bounds on the partition: a cap on how many regions
    one walk carries, read from the `path_region_cap` setting, and a merge of
    the regions one rule decided alike."""

    def test_the_walk_stops_at_the_cap_and_reports_what_is_left(self, monkeypatch):
        monkeypatch.setattr(firewall, "Settings", lambda: SimpleNamespace(path_region_cap=2))

        def drop_port(uid, pos, port):
            return _rule(
                uid=uid, pos=pos, action="drop", src_any=True, dst_any=True, protos=["tcp"], ports=[port]
            )

        rules = [
            drop_port("fw:r1", 1, "10"),
            drop_port("fw:r2", 2, "20"),
            drop_port("fw:r3", 3, "30"),
            _rule(uid="fw:r4", pos=4, action="accept", src_any=True, dst_any=True, svc_any=True),
        ]
        regions = _regions(rules, "1-100", "tcp")
        assert [reg[4] for reg in regions] == [
            [(0, 10, 10)],
            [(0, 20, 20)],
            [(0, 1, 9), (0, 11, 19), (0, 21, 100)],
        ]
        truncated = regions[-1][0]
        assert classify_action(truncated["action"]) == INDETERMINATE
        assert "path_region_cap" in truncated["indeterminate_reason"]
        assert "2 regions" in truncated["indeterminate_reason"]

    def test_the_default_cap_comes_from_the_setting(self):
        assert Settings().path_region_cap == 64

    def test_three_device_wide_candidates_cross_multiply_past_a_small_cap(self, monkeypatch):
        monkeypatch.setattr(firewall, "Settings", lambda: SimpleNamespace(path_region_cap=3))

        def candidate(uid, name):
            return {
                "rb_uid": uid,
                "rb_name": name,
                "vendor": "checkpoint",
                "af": None,
                "default_action": "drop",
                "default_action_unknown": False,
                "global_state_policy": None,
                "match_context": None,
                "chain": None,
                "approximate": False,
            }

        rows = [candidate("fw:a", "A"), candidate("fw:b", "B"), candidate("fw:c", "C")]

        def drop_port(uid, port):
            return _rule(
                uid=uid, pos=1, action="drop", src_any=True, dst_any=True, protos=["tcp"], ports=[port]
            )

        def accept_any(uid):
            return _rule(uid=uid, pos=2, action="accept", src_any=True, dst_any=True, svc_any=True)

        rules_by_rb = {
            "fw:a": [drop_port("fw:a1", "10"), accept_any("fw:a2")],
            "fw:b": [drop_port("fw:b1", "20"), accept_any("fw:b2")],
            "fw:c": [drop_port("fw:c1", "30"), accept_any("fw:c2")],
        }

        def fake_read(s, q, **p):
            if "ENFORCES" in q:
                return rows
            if "HAS_RULE" in q:
                return rules_by_rb[p["rb"]]
            return []

        monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
        monkeypatch.setattr(path, "_read", fake_read)
        src, dst = path._intervals(["10.0.0.5"]), path._intervals(["10.9.9.9"])
        v = path._device_rulebase_verdict(None, "dev:fw1", "if:in", "if:out", src, dst, "1-100", "tcp", 4)

        assert isinstance(v, list)
        # the un-bounded cross product would return 4 regions here; the
        # fold's own cap keeps it at the setting, the same ceiling
        # `_cap_regions` enforces within one candidate's own walk.
        assert len(v) == 3
        capped = next(d for d in v if classify_action(d["action"]) == INDETERMINATE)
        assert "path_region_cap" in capped["indeterminate_reason"]
        assert "3 regions" in capped["indeterminate_reason"]
        kept = [d for d in v if d is not capped]
        assert {d["rule_uid"] for d in kept} == {"fw:a1", "fw:b1"}

    def test_adjacent_regions_one_rule_decided_alike_come_back_as_one(self):
        rules = [
            _rule(
                uid="fw:r1",
                pos=1,
                action="drop",
                src_any=True,
                dst_any=True,
                protos=["tcp", "tcp"],
                ports=["440-442", "443"],
            ),
            _rule(uid="fw:r2", pos=2, action="accept", src_any=True, dst_any=True, svc_any=True),
        ]
        regions = _regions(rules, "435-450", "tcp")
        assert len(regions) == 2
        denied = next(reg for reg in regions if reg[0]["uid"] == "fw:r1")
        assert denied[4] == [(0, 440, 443)]

    def test_a_deny_never_merges_into_a_region_with_another_outcome(self):
        """440-442 denied and 443 accepted are adjacent intervals of one
        protocol, and they stay two regions: the merge folds regions that
        carry the same verdict, never regions that merely touch."""
        rules = [
            _rule(
                uid="fw:r1",
                pos=1,
                action="drop",
                src_any=True,
                dst_any=True,
                protos=["tcp"],
                ports=["440-442"],
            ),
            _rule(
                uid="fw:r2", pos=2, action="accept", src_any=True, dst_any=True, protos=["tcp"], ports=["443"]
            ),
            _rule(uid="fw:r3", pos=3, action="accept", src_any=True, dst_any=True, svc_any=True),
        ]
        regions = _regions(rules, "440-450", "tcp")
        assert [(reg[0]["uid"], reg[4]) for reg in regions] == [
            ("fw:r1", [(0, 440, 442)]),
            ("fw:r2", [(0, 443, 443)]),
            ("fw:r3", [(0, 444, 450)]),
        ]


# --- an interface ACL is a candidate at the stage its binding direction names ------------


def _direction_verdict(acl_direction, out_if="if:out"):
    return path._device_rulebase_verdict(
        None,
        "dev:fw1",
        "if:in",
        out_if,
        path._intervals(["10.0.0.5"]),
        path._intervals(["8.8.8.8"]),
        443,
        "tcp",
        4,
        acl_direction=acl_direction,
    )


def _two_interface_acls(monkeypatch):
    outbound = {
        **_ACL_RB,
        "rb_uid": "cisco:edge-out",
        "rb_name": "EDGE-OUT",
        "acl_bindings": _bound(("Gi0/2", "out")),
    }
    inbound = {
        **_ACL_RB,
        "rb_uid": "cisco:edge-in",
        "rb_name": "EDGE-IN",
        "acl_bindings": _bound(("Gi0/1", "in")),
    }
    rules = {
        "cisco:edge-out": [
            _rule(
                uid="cisco:edge-out:1",
                action="deny",
                src_any=True,
                dst_any=True,
                svc_any=True,
            )
        ],
        "cisco:edge-in": [
            _rule(
                uid="cisco:edge-in:1",
                action="permit",
                src_any=True,
                dst_any=True,
                svc_any=True,
            )
        ],
    }
    _acl_read(monkeypatch, [outbound, inbound], rules, {"if:in": "Gi0/1", "if:out": "Gi0/2"})


def test_the_filter_stage_judges_the_inbound_list_and_leaves_the_outbound_one(monkeypatch):
    _two_interface_acls(monkeypatch)
    v = _direction_verdict("in")
    assert v["rb_uid"] == "cisco:edge-in"
    assert classify_action(v["action"]) == PERMIT


def test_the_egress_stage_judges_the_outbound_list_and_leaves_the_inbound_one(monkeypatch):
    _two_interface_acls(monkeypatch)
    v = _direction_verdict("out")
    assert v["rb_uid"] == "cisco:edge-out"
    assert classify_action(v["action"]) == DENY


def test_no_direction_judges_both_lists(monkeypatch):
    _two_interface_acls(monkeypatch)
    v = _direction_verdict(None)
    assert v["rb_uid"] == "cisco:edge-out"
    assert classify_action(v["action"]) == DENY


def test_an_outbound_list_on_an_unresolved_egress_stays_undecided_at_the_filter_stage(monkeypatch):
    _two_interface_acls(monkeypatch)
    v = _direction_verdict("in", out_if=None)
    assert v["rb_uid"] == "cisco:edge-out"
    assert classify_action(v["action"]) == INDETERMINATE
    assert "egress interface" in v["indeterminate_reason"]


# --- one access list, one rulebase, bound to its interfaces by PROTECTED_BY ----------------
#
# The collector writes one FwRulebase per device and ACL name and one PROTECTED_BY edge
# per binding. The candidate read returns those edges as `acl_bindings`, and the gate
# judges the list on a hop only where one of them names the hop's ingress interface
# in direction 'in' or its egress interface in direction 'out'.

_SHARED = "cisco:shared"


def _shared_acl(monkeypatch, bindings, names, reads=None, action="deny"):
    """One list of a single match-all rule bound by `bindings`; `names` maps interface
    uids to names. `reads`, when given, collects the uid of every rules read."""
    rb = {**_ACL_RB, "rb_uid": _SHARED, "rb_name": "SHARED", "acl_bindings": _bound(*bindings)}
    rules = [_rule(uid=f"{_SHARED}:1", action=action, src_any=True, dst_any=True, svc_any=True)]
    name_rows = [{"uid": u, "name": n} for u, n in names.items()]

    def fake_read(s, q, **p):
        if "ENFORCES" in q:
            return [rb]
        if "i.uid IN" in q:
            return name_rows
        if reads is not None:
            reads.append(p.get("rb"))
        return rules

    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(path, "_read", fake_read)


def _hop(in_if, out_if, acl_direction=None, considered=None):
    return path._device_rulebase_verdict(
        None,
        "dev:fw1",
        in_if,
        out_if,
        path._intervals(["10.0.0.5"]),
        path._intervals(["8.8.8.8"]),
        443,
        "tcp",
        4,
        considered=considered,
        acl_direction=acl_direction,
    )


_NAMES = {"if:a": "Gi0/1", "if:b": "Gi0/2", "if:c": "Gi0/3", "if:d": "Gi0/4"}


def test_one_acl_bound_to_three_interfaces_judges_a_hop_entering_by_any_of_them(monkeypatch):
    _shared_acl(monkeypatch, [("Gi0/1", "in"), ("Gi0/2", "in"), ("Gi0/3", "in")], _NAMES)
    for ingress in ("if:a", "if:b", "if:c"):
        v = _hop(ingress, "if:d")
        assert v["rb_uid"] == _SHARED
        assert classify_action(v["action"]) == DENY


def test_one_acl_bound_to_three_interfaces_is_excluded_on_a_hop_using_none_of_them(monkeypatch):
    _shared_acl(monkeypatch, [("Gi0/1", "in"), ("Gi0/2", "in"), ("Gi0/3", "in")], _NAMES)
    considered: list[str] = []
    assert _hop("if:d", "if:a", considered=considered) is None
    assert considered == [_SHARED]


def test_a_binding_judges_only_in_its_own_direction(monkeypatch):
    """Bound inbound on Gi0/1: a hop leaving by Gi0/1 is not governed by it."""
    _shared_acl(monkeypatch, [("Gi0/1", "in")], _NAMES)
    assert _hop("if:d", "if:a") is None
    assert classify_action(_hop("if:a", "if:d")["action"]) == DENY


def test_an_acl_bound_in_and_out_on_one_interface_is_judged_at_both_stages(monkeypatch):
    """`ip access-group SHARED in` and `ip access-group SHARED out` on Gi0/1: one
    rulebase with two PROTECTED_BY edges. Entering by Gi0/1 it is judged at the
    filter stage only; leaving by Gi0/1 at the egress stage only; a hop that
    uses Gi0/1 on neither side is not judged at all. Both views share one
    read of the rules."""
    reads: list[str] = []
    _shared_acl(monkeypatch, [("Gi0/1", "in"), ("Gi0/1", "out")], _NAMES, reads)

    entering = _hop("if:a", "if:b", acl_direction="in")
    assert entering["rb_uid"] == _SHARED and classify_action(entering["action"]) == DENY
    assert _hop("if:a", "if:b", acl_direction="out") is None

    leaving = _hop("if:b", "if:a", acl_direction="out")
    assert leaving["rb_uid"] == _SHARED and classify_action(leaving["action"]) == DENY
    assert _hop("if:b", "if:a", acl_direction="in") is None

    assert _hop("if:b", "if:c", acl_direction="in") is None
    assert _hop("if:b", "if:c", acl_direction="out") is None
    # no stage of its own: both directions judged here, the rules read once
    reads.clear()
    assert classify_action(_hop("if:a", "if:a")["action"]) == DENY
    assert reads == [_SHARED]


def test_an_acl_bound_in_and_out_keeps_its_unresolved_egress_undecided(monkeypatch):
    _shared_acl(monkeypatch, [("Gi0/1", "in"), ("Gi0/2", "out")], {"if:a": "Gi0/1"}, action="permit")
    v = _hop("if:a", "if:unnamed", acl_direction="in")
    assert classify_action(v["action"]) == INDETERMINATE
    assert "'Gi0/2'" in v["indeterminate_reason"]
    assert "egress interface name could not be resolved" in v["indeterminate_reason"]


def test_the_verdict_names_the_binding_it_judged(monkeypatch):
    _shared_acl(monkeypatch, [("Gi0/1", "in"), ("Gi0/2", "in"), ("Gi0/3", "out")], _NAMES)
    assert _hop("if:b", "if:d")["rb_name"] == "SHARED (in on Gi0/2)"
    assert _hop("if:d", "if:c", acl_direction="out")["rb_name"] == "SHARED (out on Gi0/3)"


# --- a binding to an interface the device did not report ---------------------------------
#
# The collector keeps it on the rulebase as "<name> <direction>" (`unreported_bindings`,
# read as `acl_unreported`): there is no Interface node to draw an edge from.


def _unreported_acl(monkeypatch, names):
    rb = {
        **_ACL_RB,
        "rb_uid": _SHARED,
        "rb_name": "SHARED",
        "acl_bindings": [],
        "acl_unreported": ["GigabitEthernet9/9/9 in"],
    }
    rules = [_rule(uid=f"{_SHARED}:1", action="deny", src_any=True, dst_any=True, svc_any=True)]
    name_rows = [{"uid": u, "name": n} for u, n in names.items()]
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    monkeypatch.setattr(
        path, "_read", lambda s, q, **p: [rb] if "ENFORCES" in q else name_rows if "i.uid IN" in q else rules
    )


def test_an_unreported_binding_leaves_an_unresolved_ingress_undecided(monkeypatch):
    _unreported_acl(monkeypatch, {})
    v = _hop("if:a", "if:b")
    assert classify_action(v["action"]) == INDETERMINATE
    assert "'GigabitEthernet9/9/9'" in v["indeterminate_reason"]
    assert v["rb_name"] == "SHARED (in on GigabitEthernet9/9/9)"


def test_an_unreported_binding_excludes_a_hop_on_another_resolved_interface(monkeypatch):
    _unreported_acl(monkeypatch, _NAMES)
    considered: list[str] = []
    assert _hop("if:a", "if:b", considered=considered) is None
    assert considered == [_SHARED]


def _legacy_rb(rb_uid, name):
    return {**_ACL_RB, "rb_uid": rb_uid, "rb_name": name, "acl_bindings": [], "acl_unreported": None}


def _legacy_rule(rb_uid, action, **scope):
    return _rule(uid=f"{rb_uid}:1", action=action, src_any=True, dst_any=True, svc_any=True, **scope)


def test_a_per_binding_acl_bound_to_the_ingress_denies(monkeypatch):
    rb = _legacy_rb("cisco:acl:gi0-1:in:edge-in", "EDGE-IN in Gi0/1")
    rules = {rb["rb_uid"]: [_legacy_rule(rb["rb_uid"], "deny", in_if="Gi0/1")]}
    _acl_read(monkeypatch, [rb], rules, {"if:in": "Gi0/1"})
    v = _acl_verdict()
    assert v["rb_uid"] == rb["rb_uid"]
    assert classify_action(v["action"]) == DENY
    assert v["rb_name"] == "EDGE-IN in Gi0/1"


def test_a_per_binding_acl_on_another_interface_is_excluded_not_defaulted_to_deny(monkeypatch):
    unrelated = _legacy_rb("cisco:acl:mgmt0:out:mgmt-out", "MGMT-OUT out Mgmt0")
    applicable = _legacy_rb("cisco:acl:gi0-1:in:edge-in", "EDGE-IN in Gi0/1")
    rules = {
        unrelated["rb_uid"]: [_legacy_rule(unrelated["rb_uid"], "deny", out_if="Mgmt0")],
        applicable["rb_uid"]: [_legacy_rule(applicable["rb_uid"], "permit", in_if="Gi0/1")],
    }
    _acl_read(monkeypatch, [unrelated, applicable], rules, {"if:in": "Gi0/1", "if:out": "Gi0/2"})
    considered: list[str] = []
    v = path._device_rulebase_verdict(
        None,
        "dev:fw1",
        "if:in",
        "if:out",
        path._intervals(["10.0.0.5"]),
        path._intervals(["8.8.8.8"]),
        443,
        "tcp",
        4,
        considered=considered,
    )
    assert v["rb_uid"] == applicable["rb_uid"]
    assert classify_action(v["action"]) == PERMIT
    assert sorted(considered) == sorted([unrelated["rb_uid"], applicable["rb_uid"]])


def test_a_per_binding_acl_on_an_unresolved_egress_is_undecided(monkeypatch):
    rb = _legacy_rb("cisco:acl:mgmt0:out:mgmt-out", "MGMT-OUT out Mgmt0")
    rules = {rb["rb_uid"]: [_legacy_rule(rb["rb_uid"], "deny", out_if="Mgmt0")]}
    _acl_read(monkeypatch, [rb], rules, {})
    v = _acl_verdict()
    assert classify_action(v["action"]) == INDETERMINATE
    assert "Mgmt0" in v["indeterminate_reason"]


def test_per_binding_acls_are_judged_at_the_stage_their_direction_names(monkeypatch):
    outbound = _legacy_rb("cisco:acl:gi0-2:out:edge-out", "EDGE-OUT out Gi0/2")
    inbound = _legacy_rb("cisco:acl:gi0-1:in:edge-in", "EDGE-IN in Gi0/1")
    rules = {
        outbound["rb_uid"]: [_legacy_rule(outbound["rb_uid"], "deny", out_if="Gi0/2")],
        inbound["rb_uid"]: [_legacy_rule(inbound["rb_uid"], "permit", in_if="Gi0/1")],
    }
    _acl_read(monkeypatch, [outbound, inbound], rules, {"if:in": "Gi0/1", "if:out": "Gi0/2"})
    filter_stage = _direction_verdict("in")
    assert filter_stage["rb_uid"] == inbound["rb_uid"]
    assert classify_action(filter_stage["action"]) == PERMIT
    egress_stage = _direction_verdict("out")
    assert egress_stage["rb_uid"] == outbound["rb_uid"]
    assert classify_action(egress_stage["action"]) == DENY


def test_a_deny_contract_and_a_permit_contract_are_indeterminate_in_either_row_order(aci):
    """Contract A permits ip any, contract B denies tcp/22. The answer must not
    depend on which row the query returns first, and the precedence between two
    contracts is not collected."""
    permit_any = {
        "uid": "k-a",
        "name": "any",
        "entries": [{"proto": "unspecified", "from_port": "unspecified", "to_port": "unspecified"}],
    }
    deny_ssh = {
        "uid": "k-b",
        "name": "no-ssh",
        "entries": [{"proto": "tcp", "from_port": 22, "to_port": 22, "action": "deny"}],
    }
    aci["ends"] = _ends()
    verdicts = []
    for contracts in ([permit_any, deny_ssh], [deny_ssh, permit_any]):
        aci["contracts"] = contracts
        verdicts.append(_aci(port=22))
    assert [v["action"] for v in verdicts] == [INDETERMINATE, INDETERMINATE]
    assert verdicts[0]["reason"] == verdicts[1]["reason"]
    assert "precedence between two contracts" in verdicts[0]["reason"]


def test_a_deny_entry_that_cannot_be_evaluated_stops_a_later_contracts_permit(aci):
    """Contract A denies tcp/443 from source ports 1024-65535 (not
    evaluable, the flow has no source port), contract B permits tcp/443."""
    aci["ends"] = _ends()
    aci["contracts"] = [
        {
            "uid": "k-a",
            "name": "deny-high-sport",
            "entries": [
                {
                    "proto": "tcp",
                    "from_port": 443,
                    "to_port": 443,
                    "s_from_port": "1024",
                    "s_to_port": "65535",
                    "action": "deny",
                }
            ],
        },
        {"uid": "k-b", "name": "https", "entries": [{"proto": "tcp", "from_port": 443, "to_port": 443}]},
    ]
    v = _aci(port=443)
    assert v["action"] == INDETERMINATE
    assert v["contract"] == "deny-high-sport"


def test_two_contracts_that_both_permit_permit(aci):
    aci["ends"] = _ends()
    aci["contracts"] = [
        {"uid": "k-b", "name": "https", "entries": [{"proto": "tcp", "from_port": 443, "to_port": 443}]},
        {
            "uid": "k-a",
            "name": "any",
            "entries": [{"proto": "unspecified", "from_port": "unspecified", "to_port": "unspecified"}],
        },
    ]
    v = _aci(port=443)
    assert v["action"] == PERMIT
    assert v["contract"] == "any"


def test_an_unevaluable_permit_entry_beside_a_matching_permit_entry_permits(aci):
    """A sibling permit entry with tcpRules cannot change a permit."""
    aci["ends"] = _ends()
    aci["contracts"] = [
        {
            "uid": "k1",
            "name": "https",
            "entries": [
                {"proto": "tcp", "from_port": 443, "to_port": 443},
                {"proto": "tcp", "from_port": 443, "to_port": 443, "tcp_rules": "est"},
            ],
        }
    ]
    assert _aci(port=443)["action"] == PERMIT


def test_a_contract_in_the_reverse_orientation_makes_no_contract_indeterminate(aci):
    """The source EPG provides and the destination EPG consumes a contract;
    the provider-to-consumer direction is not evaluated, so no implicit deny."""
    aci["ends"] = _ends()
    aci["contracts"] = [
        {
            "uid": "k1",
            "name": "db-to-web",
            "orientation": "reverse",
            "entries": [{"proto": "unspecified", "from_port": "unspecified", "to_port": "unspecified"}],
        }
    ]
    v = _aci(port=1521)
    assert v["action"] == INDETERMINATE
    assert "db-to-web" in v["reason"]


def test_a_reverse_contract_beside_a_non_matching_forward_contract_is_indeterminate(aci):
    aci["ends"] = _ends()
    aci["contracts"] = [
        {"uid": "k1", "name": "ssh-only", "entries": [{"proto": "tcp", "from_port": 22, "to_port": 22}]},
        {
            "uid": "k2",
            "name": "db-to-web",
            "orientation": "reverse",
            "entries": [{"proto": "unspecified", "from_port": "unspecified", "to_port": "unspecified"}],
        },
    ]
    v = _aci(port=1521)
    assert v["action"] == INDETERMINATE
    assert "provider-to-consumer" in v["reason"]


@pytest.mark.parametrize(
    ("bypass", "words"),
    [
        ("vzany", "vzAny"),
        ("preferred-group", "preferred group"),
        ("esg", "endpoint security groups"),
        ("not-collected", "not collected"),
        (None, "not collected"),
    ],
)
def test_a_vrf_with_vzany_preferred_group_or_esg_does_not_implicitly_deny(aci, bypass, words):
    aci["ends"] = [{**end, "contract_bypass": bypass} for end in _ends()]
    aci["contracts"] = []
    v = _aci()
    assert v["action"] == INDETERMINATE
    assert words in v["reason"]


def test_a_vrf_flag_does_not_change_an_explicit_contract_permit(aci):
    aci["ends"] = [{**end, "contract_bypass": "vzany"} for end in _ends()]
    aci["contracts"] = [
        {"uid": "k1", "name": "web-to-db", "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521}]}
    ]
    assert _aci(port=1521)["action"] == PERMIT
