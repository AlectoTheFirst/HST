"""The ZPA brokered stage's own building blocks: the first-match access-rule
evaluator, segment address resolution, and connector selection/address.
"""

# ruff: noqa: F811

import json

from tests.test_path_trace import graph  # noqa: F401

from hst.path.gates import Stage, zpa

IDENTITY = "idg:scim:sales"
SEGMENT = "zpa:acme:seg:2001"
SEGGRP = "zpa:acme:seggrp:100"


def _rule(**kw):
    base = {
        "uid": "zpa:acme:rule:100",
        "name": "sales-to-webshop",
        "position": 1,
        "action": "allow",
        "applies_to_all_identities": None,
        "conditions": None,
        "identity_named": True,
    }
    base.update(kw)
    return base


def _connector(**kw):
    base = {"uid": "zpa:acme:connector:dc1-01", "name": "dc1-conn-01", "health": "healthy"}
    base.update(kw)
    return base


# --- Stage enum ----------------------------------------------------------------------------


def test_the_four_brokered_stages_sort_before_src_endpoint_and_do_not_collide():
    brokered = [Stage.IDENTITY, Stage.BROKER, Stage.ACCESS_RULE, Stage.CONNECTOR]
    for s in brokered:
        assert s < Stage.SRC_ENDPOINT
    values = [int(s) for s in Stage]
    assert len(values) == len(set(values)), "a Stage value collides with another"


# --- _resolve_segment_refs and _identity_group --------------------------------------------


def test_resolve_segment_refs_by_uid_or_domain(graph):
    graph.segment_ref["webshop.corp.example"] = {"uid": SEGMENT}
    assert zpa._resolve_segment_refs(None, "webshop.corp.example") == [SEGMENT]
    graph.segment_ref[SEGMENT] = {"uid": SEGMENT}
    assert zpa._resolve_segment_refs(None, SEGMENT) == [SEGMENT]


def test_resolve_segment_refs_empty_when_unmatched(graph):
    assert zpa._resolve_segment_refs(None, "no-such-domain.example") == []


def test_resolve_segment_refs_keeps_every_segment_that_lists_the_domain(graph):
    graph.segment_ref["app.corp.example"] = [{"uid": "zpa:seg:a"}, {"uid": "zpa:seg:b"}]
    assert zpa._resolve_segment_refs(None, "app.corp.example") == ["zpa:seg:a", "zpa:seg:b"]


def test_identity_group_reads_name(graph):
    graph.identity_groups[IDENTITY] = {"uid": IDENTITY, "name": "sales"}
    assert zpa._identity_group(None, IDENTITY) == {"uid": IDENTITY, "name": "sales"}


# --- _access_rule_match: first-match over GRANTS|DENIES and FOR --------------------------


def test_an_explicit_identity_rule_wins_over_a_lower_priority_allow_all(graph):
    explicit = _rule(uid="r:1", position=1, action="allow", identity_named=True)
    allow_all = _rule(
        uid="r:2", position=2, action="allow", identity_named=False, applies_to_all_identities=True
    )
    graph.access_rules[(IDENTITY, SEGMENT)] = [explicit, allow_all]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert not decision.indeterminate
    assert decision.action == "allow"
    assert decision.rule["uid"] == "r:1"


def test_falls_through_to_an_allow_all_rule_when_no_identity_specific_rule_matches(graph):
    other_identity = _rule(uid="r:1", position=1, action="deny", identity_named=False)
    allow_all = _rule(
        uid="r:2", position=2, action="allow", identity_named=False, applies_to_all_identities=True
    )
    graph.access_rules[(IDENTITY, SEGMENT)] = [other_identity, allow_all]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert not decision.indeterminate
    assert decision.action == "allow"
    assert decision.rule["uid"] == "r:2"


def test_indeterminate_named_when_no_rule_matches_the_segment_at_all(graph):
    graph.access_rules[(IDENTITY, SEGMENT)] = []
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate
    assert decision.rule is None
    assert SEGMENT in decision.reason


def test_indeterminate_named_when_rules_target_the_segment_but_none_this_identity(graph):
    graph.access_rules[(IDENTITY, SEGMENT)] = [_rule(uid="r:1", identity_named=False)]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate
    assert IDENTITY in decision.reason and SEGMENT in decision.reason


def test_matches_via_for_on_a_segment_group_through_a_recorded_member_of_edge(graph):
    """A rule whose FOR names the ZpaSegmentGroup matches the segment, and
    the query asked for is the one that finds it through the group: the
    rule is stored under the group, the request names the segment, and the
    membership edge is what joins them."""
    via_group = _rule(uid="r:1", position=1, action="allow", identity_named=True)
    graph.access_rules[(IDENTITY, SEGGRP)] = [via_group]
    graph.segment_groups[SEGMENT] = [SEGGRP]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert not decision.indeterminate
    assert decision.rule["uid"] == "r:1"


def test_a_segment_group_rule_does_not_match_without_the_member_of_edge(graph):
    """Group membership is never inferred: with no recorded MEMBER_OF edge
    the same rule is not FOR this segment at all."""
    graph.access_rules[(IDENTITY, SEGGRP)] = [_rule(uid="r:1", position=1, identity_named=True)]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate
    assert decision.rule is None
    assert SEGMENT in decision.reason


def test_the_access_rule_query_joins_a_segment_group_by_the_member_of_edge():
    """The join itself is Cypher a FakeGraph cannot execute, so the clause is
    pinned here, the same way test_path_lb.py pins the RedundancyGroup arm of
    the VIP binding query."""
    assert "MEMBER_OF]->(target:ZpaSegmentGroup)" in zpa._ACCESS_RULE_QUERY
    assert "em._retired_at IS NULL" in zpa._ACCESS_RULE_QUERY


def test_a_deny_at_a_lower_position_than_an_unrelated_allow_is_not_shadowed(graph):
    unrelated_deny = _rule(uid="r:1", position=1, action="deny", identity_named=False)
    matching_allow = _rule(uid="r:2", position=2, action="allow", identity_named=True)
    graph.access_rules[(IDENTITY, SEGMENT)] = [unrelated_deny, matching_allow]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert not decision.indeterminate
    assert decision.action == "allow"
    assert decision.rule["uid"] == "r:2"


def test_two_rules_tied_at_the_winning_position_are_indeterminate(graph):
    a = _rule(uid="r:1", position=1, action="allow", identity_named=True)
    b = _rule(uid="r:2", position=1, action="deny", identity_named=True, name="also-position-1")
    graph.access_rules[(IDENTITY, SEGMENT)] = [a, b]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate
    assert decision.rule is None
    assert "2 access rules tie" in decision.reason
    assert "sales-to-webshop" in decision.reason and "also-position-1" in decision.reason


def test_an_unrecognized_condition_operand_type_is_indeterminate_naming_it(graph):
    conditions = json.dumps([{"operator": "AND", "operands": [{"type": "POSTURE", "rhs": "p1"}]}])
    rule = _rule(uid="r:1", position=1, action="allow", identity_named=True, conditions=conditions)
    graph.access_rules[(IDENTITY, SEGMENT)] = [rule]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate
    assert decision.rule["uid"] == "r:1"
    assert "POSTURE" in decision.reason


def test_a_known_condition_shape_is_not_flagged_unsupported(graph):
    conditions = json.dumps(
        [
            {"operator": "OR", "operands": [{"type": "APP", "rhs": "2001"}]},
            {"operator": "OR", "operands": [{"type": "SCIM_GROUP", "rhs": "sales"}]},
        ]
    )
    rule = _rule(uid="r:1", position=1, action="allow", identity_named=True, conditions=conditions)
    graph.access_rules[(IDENTITY, SEGMENT)] = [rule]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert not decision.indeterminate
    assert decision.action == "allow"


def test_two_and_ed_scim_group_condition_blocks_are_indeterminate(graph):
    conditions = json.dumps(
        [
            {"operator": "AND", "operands": [{"type": "SCIM_GROUP", "rhs": "sales"}]},
            {"operator": "AND", "operands": [{"type": "SCIM_GROUP", "rhs": "on-prem-managed"}]},
            {"operator": "OR", "operands": [{"type": "APP", "rhs": "2001"}]},
        ]
    )
    rule = _rule(uid="r:1", position=1, action="allow", identity_named=True, conditions=conditions)
    graph.access_rules[(IDENTITY, SEGMENT)] = [rule]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate
    assert decision.action is None
    assert decision.rule["uid"] == "r:1"
    assert "identity condition blocks" in decision.reason


def test_two_and_ed_application_condition_blocks_are_indeterminate(graph):
    conditions = json.dumps(
        [
            {"operator": "AND", "operands": [{"type": "APP", "rhs": "2001"}]},
            {"operator": "AND", "operands": [{"type": "APP_GROUP", "rhs": "100"}]},
        ]
    )
    rule = _rule(uid="r:1", position=1, action="allow", identity_named=True, conditions=conditions)
    graph.access_rules[(IDENTITY, SEGMENT)] = [rule]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate
    assert "application condition blocks" in decision.reason


def test_a_condition_block_with_no_collected_operator_is_indeterminate(graph):
    """A payload that spells the operator key differently stores it as null;
    the block's own reading is then unknown, so the rule is not evaluated."""
    conditions = json.dumps([{"operator": None, "operands": [{"type": "SCIM_GROUP", "rhs": "sales"}]}])
    rule = _rule(uid="r:1", position=1, action="allow", identity_named=True, conditions=conditions)
    graph.access_rules[(IDENTITY, SEGMENT)] = [rule]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate
    assert "operator" in decision.reason


def test_a_condition_block_with_no_operands_is_indeterminate(graph):
    conditions = json.dumps(
        [
            {"operator": "OR", "operands": []},
            {"operator": "OR", "operands": [{"type": "SCIM_GROUP", "rhs": "sales"}]},
            {"operator": "OR", "operands": [{"type": "APP", "rhs": "2001"}]},
        ]
    )
    rule = _rule(uid="r:1", position=1, action="allow", identity_named=True, conditions=conditions)
    graph.access_rules[(IDENTITY, SEGMENT)] = [rule]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate
    assert "no operands" in decision.reason


def test_a_condition_operator_this_engine_does_not_read_is_indeterminate(graph):
    conditions = json.dumps([{"operator": "NOT", "operands": [{"type": "SCIM_GROUP", "rhs": "sales"}]}])
    rule = _rule(uid="r:1", position=1, action="allow", identity_named=True, conditions=conditions)
    graph.access_rules[(IDENTITY, SEGMENT)] = [rule]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate
    assert "NOT" in decision.reason


def test_two_operands_joined_by_and_inside_one_block_are_indeterminate(graph):
    """Operands inside a block are read as "any one matches", which is OR; an
    AND across them is a different rule than the edges can express."""
    conditions = json.dumps(
        [
            {
                "operator": "AND",
                "operands": [{"type": "SCIM_GROUP", "rhs": "sales"}, {"type": "SCIM_GROUP", "rhs": "ops"}],
            }
        ]
    )
    rule = _rule(uid="r:1", position=1, action="allow", identity_named=True, conditions=conditions)
    graph.access_rules[(IDENTITY, SEGMENT)] = [rule]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate
    assert "not OR" in decision.reason


def test_a_non_integer_position_is_indeterminate_naming_the_rule(graph):
    """First-match is an integer order. A rule whose position is not one
    would be ordered against the others by a string compare, which is not the
    order the broker runs."""
    graph.access_rules[(IDENTITY, SEGMENT)] = [
        _rule(uid="r:1", position="high", name="unordered-rule", identity_named=True),
        _rule(uid="r:2", position=2, identity_named=True),
    ]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate
    assert decision.rule is None
    assert "unordered-rule" in decision.reason


def test_positions_are_compared_as_integers_not_strings(graph):
    """Position "9" sorts after "10" as a string and before it as an integer:
    the integer order is the one the broker runs."""
    graph.access_rules[(IDENTITY, SEGMENT)] = [
        _rule(uid="r:1", position="10", action="deny", identity_named=True),
        _rule(uid="r:2", position="9", action="allow", identity_named=True),
    ]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert not decision.indeterminate
    assert decision.rule["uid"] == "r:2"
    assert decision.action == "allow"


def test_an_unrecognized_action_value_is_indeterminate(graph):
    rule = _rule(uid="r:1", position=1, action="bypass", identity_named=True)
    graph.access_rules[(IDENTITY, SEGMENT)] = [rule]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate
    assert decision.rule["uid"] == "r:1"


# --- _segment_port_match: the segment's own published ports -------------------------------


def test_a_port_inside_a_collected_range_matches(graph):
    graph.segment_ports[SEGMENT] = {"tcp": ["440", "445", "8443", "8443"], "udp": None}
    match = zpa._segment_port_match(None, SEGMENT, 8443, "tcp")
    assert match.matched
    assert not match.indeterminate


def test_a_port_outside_every_collected_range_is_a_named_no_match(graph):
    graph.segment_ports[SEGMENT] = {"tcp": ["443", "443"], "udp": None}
    match = zpa._segment_port_match(None, SEGMENT, 22, "tcp")
    assert not match.matched
    assert not match.indeterminate
    assert SEGMENT in match.reason and "443-443" in match.reason


def test_uncollected_port_ranges_are_indeterminate_naming_the_segment(graph):
    graph.segment_ports[SEGMENT] = {"tcp": None, "udp": ["53", "53"]}
    match = zpa._segment_port_match(None, SEGMENT, 443, "tcp")
    assert not match.matched
    assert match.indeterminate
    assert SEGMENT in match.reason


def test_udp_is_compared_against_the_udp_ranges(graph):
    graph.segment_ports[SEGMENT] = {"tcp": ["443", "443"], "udp": ["53", "53"]}
    assert zpa._segment_port_match(None, SEGMENT, 53, "udp").matched
    assert not zpa._segment_port_match(None, SEGMENT, 443, "udp").matched


def test_port_ranges_that_are_not_from_to_pairs_are_indeterminate(graph):
    graph.segment_ports[SEGMENT] = {"tcp": ["443"], "udp": None}
    match = zpa._segment_port_match(None, SEGMENT, 443, "tcp")
    assert match.indeterminate
    assert SEGMENT in match.reason


def test_a_proto_with_no_collected_ranges_is_indeterminate(graph):
    graph.segment_ports[SEGMENT] = {"tcp": ["443", "443"], "udp": None}
    match = zpa._segment_port_match(None, SEGMENT, 8, "icmp")
    assert match.indeterminate
    assert "icmp" in match.reason


def test_no_port_or_proto_states_nothing_to_compare(graph):
    match = zpa._segment_port_match(None, SEGMENT, None, "tcp")
    assert match.matched
    assert match.reason is None


# --- _segment_resolution: RESOLVES_TO chain -----------------------------------------------


def test_resolves_a_segment_through_dns_record_to_an_ip_address(graph):
    graph.segment_resolution[SEGMENT] = [{"addr": "10.0.30.10"}]
    resolution = zpa._segment_resolution(None, SEGMENT)
    assert not resolution.indeterminate
    assert resolution.addresses == ["10.0.30.10"]


def test_segment_resolution_indeterminate_and_named_when_no_edge_exists(graph):
    graph.segment_resolution[SEGMENT] = []
    resolution = zpa._segment_resolution(None, SEGMENT)
    assert resolution.indeterminate
    assert resolution.addresses == []
    assert SEGMENT in resolution.reason


# --- _connector_selection: D-LB3 posture, adapted --------------------------------------


def test_picks_the_sole_healthy_connector(graph):
    graph.zpa_connectors[SEGMENT] = [_connector()]
    selection = zpa._connector_selection(None, SEGMENT)
    assert not selection.collapsed
    assert selection.chosen["uid"] == "zpa:acme:connector:dc1-01"


def test_connector_selection_collapses_when_none_carries_health(graph):
    graph.zpa_connectors[SEGMENT] = [_connector(health=None), _connector(uid="c2", health=None)]
    selection = zpa._connector_selection(None, SEGMENT)
    assert selection.collapsed
    assert selection.chosen is None
    assert "dc1-conn-01" in selection.note


def test_connector_selection_skips_an_explicitly_unhealthy_connector(graph):
    unhealthy = _connector(uid="c:down", name="down-conn", health="unhealthy")
    healthy = _connector()
    graph.zpa_connectors[SEGMENT] = [unhealthy, healthy]
    selection = zpa._connector_selection(None, SEGMENT)
    assert not selection.collapsed
    assert selection.chosen["uid"] == "zpa:acme:connector:dc1-01"


def test_connector_selection_indeterminate_when_every_connector_is_unhealthy(graph):
    graph.zpa_connectors[SEGMENT] = [_connector(health="down")]
    selection = zpa._connector_selection(None, SEGMENT)
    assert selection.collapsed
    assert selection.chosen is None


def test_connector_selection_named_when_nothing_is_recorded(graph):
    graph.zpa_connectors[SEGMENT] = []
    selection = zpa._connector_selection(None, SEGMENT)
    assert selection.collapsed
    assert SEGMENT in selection.note


def test_a_connector_with_no_collected_health_is_not_a_candidate(graph):
    """Health that was not collected is not evidence that a connector is up.
    Where a sibling does carry health, only the ones reporting healthy are
    candidates, and the ones carrying none are named for the caller."""
    no_health = _connector(uid="c:unknown", name="unknown-conn", health=None)
    healthy = _connector()
    graph.zpa_connectors[SEGMENT] = [no_health, healthy]
    selection = zpa._connector_selection(None, SEGMENT)
    assert not selection.collapsed
    assert selection.chosen["uid"] == "zpa:acme:connector:dc1-01"
    assert [r["uid"] for r in selection.no_health] == ["c:unknown"]
    assert selection.alternates == ()


def test_connector_selection_collapses_when_the_only_candidate_lacks_health(graph):
    graph.zpa_connectors[SEGMENT] = [
        _connector(uid="c:down", name="down-conn", health="down"),
        _connector(uid="c:unknown", name="unknown-conn", health=None),
    ]
    selection = zpa._connector_selection(None, SEGMENT)
    assert selection.collapsed
    assert selection.chosen is None
    assert "down-conn" in selection.note and "unknown-conn" in selection.note


def test_connector_selection_returns_the_healthy_candidates_it_passed_over(graph):
    graph.zpa_connectors[SEGMENT] = [_connector(), _connector(uid="c:2", name="dc1-conn-02")]
    selection = zpa._connector_selection(None, SEGMENT)
    assert selection.chosen["uid"] == "zpa:acme:connector:dc1-01"
    assert [r["uid"] for r in selection.alternates] == ["c:2"]


def test_a_disabled_connector_is_never_a_candidate_whatever_its_health(graph):
    graph.zpa_connectors[SEGMENT] = [
        _connector(uid="c:off", name="off-conn", enabled=False),
        _connector(uid="c:on", name="on-conn", enabled=True),
    ]
    selection = zpa._connector_selection(None, SEGMENT)
    assert selection.chosen["uid"] == "c:on"
    assert selection.alternates == ()


def test_connector_selection_collapses_when_every_connector_is_disabled(graph):
    graph.zpa_connectors[SEGMENT] = [_connector(enabled=False)]
    selection = zpa._connector_selection(None, SEGMENT)
    assert selection.collapsed and selection.chosen is None
    assert "disabled" in selection.note and "dc1-conn-01" in selection.note


# --- _connector_address -------------------------------------------------------------------


def test_connector_address_resolves_via_runs_on_and_has_ip(graph):
    graph.connector_address["conn:1"] = [{"host_uid": "vc:vc01:vm-201", "ip": "10.0.10.6"}]
    addr = zpa._connector_address(None, "conn:1")
    assert addr.ip == "10.0.10.6"
    assert addr.reason is None


def test_connector_address_returns_the_addresses_it_passed_over(graph):
    graph.connector_address["conn:1"] = [
        {"host_uid": "vc:vc01:vm-201", "ip": "10.0.10.6"},
        {"host_uid": "vc:vc01:vm-201", "ip": "10.1.0.6"},
    ]
    addr = zpa._connector_address(None, "conn:1")
    assert addr.ip == "10.0.10.6"
    assert addr.alternates == ("10.1.0.6",)


def test_connector_address_named_when_no_runs_on_target(graph):
    graph.connector_address["conn:1"] = []
    addr = zpa._connector_address(None, "conn:1")
    assert addr.ip is None
    assert "conn:1" in addr.reason


def test_connector_address_reads_same_as_only_when_asked(graph):
    graph.connector_address["conn:1"] = []
    graph.connector_same_as["conn:1"] = [{"ip": "10.9.9.9", "confidence": 0.6}]
    assert zpa._connector_address(None, "conn:1").ip is None
    addr = zpa._connector_address(None, "conn:1", follow_same_as=True)
    assert addr.ip == "10.9.9.9" and addr.same_as_confidence == 0.6


def test_connector_address_prefers_runs_on_over_same_as(graph):
    graph.connector_address["conn:1"] = [{"host_uid": "vc:vc01:vm-201", "ip": "10.0.10.6"}]
    graph.connector_same_as["conn:1"] = [{"ip": "10.9.9.9", "confidence": 0.6}]
    addr = zpa._connector_address(None, "conn:1", follow_same_as=True)
    assert addr.ip == "10.0.10.6" and addr.same_as_confidence is None


def test_connector_address_named_when_runs_on_target_has_no_ip(graph):
    graph.connector_address["conn:1"] = [{"host_uid": "vc:vc01:vm-201", "ip": None}]
    addr = zpa._connector_address(None, "conn:1")
    assert addr.ip is None
    assert addr.reason is not None


# --- rule order on collector output: ruleOrder, not priority ------------------------------


def _scripted_access_rules(batch, identity, segment):
    """The rows `_ACCESS_RULE_QUERY` returns for `identity` and `segment`,
    built from the nodes and edges the collector wrote."""
    rows = []
    for node in batch.nodes:
        if node.label != "ZpaAccessRule":
            continue
        out = [r for r in batch.rels if r.start_uid == node.uid]
        if not any(r.rel_type == "FOR" and r.end_uid == segment for r in out):
            continue
        props = node.props
        rows.append(
            {
                "uid": node.uid,
                "name": props.get("name"),
                "position": props.get("position"),
                "action": props.get("action"),
                "applies_to_all_identities": props.get("applies_to_all_identities"),
                "conditions": props.get("conditions"),
                "identity_named": any(
                    r.rel_type in ("GRANTS", "DENIES") and r.end_uid == identity for r in out
                ),
            }
        )
    return sorted(rows, key=lambda r: (r["position"], r["uid"]))


def test_the_first_rule_by_rule_order_wins_on_collector_output(graph):
    from hst.collectors.zpa import normalize_zpa
    from hst.core import uid as uidmod

    allow_group = {
        "id": "501",
        "name": "allow-group-77",
        "action": "ALLOW",
        "ruleOrder": "1",
        "priority": "2",
        "conditions": [
            {"operator": "OR", "operands": [{"objectType": "APP", "rhs": "2001"}]},
            {"operator": "OR", "operands": [{"objectType": "SCIM_GROUP", "rhs": "77", "idpId": "idp-1"}]},
        ],
    }
    deny_all = {
        "id": "502",
        "name": "deny-app-2001",
        "action": "DENY",
        "ruleOrder": "2",
        "priority": "1",
        "conditions": [{"operator": "OR", "operands": [{"objectType": "APP", "rhs": "2001"}]}],
    }
    raw = {
        "access_rules": [allow_group, deny_all],
        "scim_groups": [
            {"id": 77, "idpId": "idp-1", "name": "group-77"},
        ],
    }
    batch = normalize_zpa(raw, tenant="acme")
    segment = uidmod.zpa("acme", "seg", "2001")
    group_77 = next(r.end_uid for r in batch.rels if r.rel_type == "GRANTS")
    other_group = "idg:another-group"

    graph.access_rules[(group_77, segment)] = _scripted_access_rules(batch, group_77, segment)
    graph.access_rules[(other_group, segment)] = _scripted_access_rules(batch, other_group, segment)

    member = zpa._access_rule_match(None, group_77, segment)
    assert not member.indeterminate
    assert member.rule["uid"] == uidmod.zpa("acme", "rule", "501")
    assert member.action == "allow"

    other = zpa._access_rule_match(None, other_group, segment)
    assert not other.indeterminate
    assert other.rule["uid"] == uidmod.zpa("acme", "rule", "502")
    assert other.action == "deny"


# --- rule scope, enabled state and the whole condition model ------------------------------


def _scoped(**kw):
    return _rule(**{"segment_named": True, "identity_scope": "listed", "app_scope": "listed", **kw})


def test_a_rule_with_no_application_condition_wins_by_order(graph):
    it_rule = _scoped(uid="r:1", position=1, action="allow", segment_named=False, app_scope="any")
    deny = _scoped(uid="r:5", position=5, action="deny", identity_scope="any", identity_named=False)
    graph.access_rules[(IDENTITY, SEGMENT)] = [it_rule, deny]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert (decision.rule["uid"], decision.action, decision.indeterminate) == ("r:1", "allow", False)


def test_a_rule_with_no_application_condition_skips_an_unnamed_identity(graph):
    it_rule = _scoped(
        uid="r:1", position=1, action="allow", segment_named=False, app_scope="any", identity_named=False
    )
    deny = _scoped(uid="r:5", position=5, action="deny", identity_scope="any", identity_named=False)
    graph.access_rules[(IDENTITY, SEGMENT)] = [it_rule, deny]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert (decision.rule["uid"], decision.action) == ("r:5", "deny")


def test_an_identity_scope_other_rule_stops_the_walk_undecided(graph):
    saml = json.dumps([{"operator": "OR", "operands": [{"type": "SAML", "rhs": "admins", "lhs": "a-1"}]}])
    first = _scoped(uid="r:1", position=1, identity_scope="other", identity_named=False, conditions=saml)
    second = _scoped(uid="r:2", position=2, action="allow")
    graph.access_rules[(IDENTITY, SEGMENT)] = [first, second]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate and decision.rule["uid"] == "r:1"
    assert "SAML" in decision.reason


def test_a_disabled_rule_is_skipped(graph):
    off = _scoped(uid="r:1", position=1, action="deny", enabled=False)
    on = _scoped(uid="r:2", position=2, action="allow", enabled=True)
    graph.access_rules[(IDENTITY, SEGMENT)] = [off, on]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert (decision.rule["uid"], decision.action) == ("r:2", "allow")


def test_an_unknown_disabled_value_is_undecided(graph):
    graph.access_rules[(IDENTITY, SEGMENT)] = [_scoped(uid="r:1", disabled_raw="7")]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate and "'7'" in decision.reason


def test_a_negated_block_is_undecided(graph):
    conditions = json.dumps(
        [
            {"operator": "OR", "operands": [{"type": "APP", "rhs": "2001"}]},
            {"operator": "OR", "negated": True, "operands": [{"type": "SCIM_GROUP", "rhs": "7"}]},
        ]
    )
    graph.access_rules[(IDENTITY, SEGMENT)] = [
        _scoped(uid="r:1", identity_scope="other", conditions=conditions)
    ]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate and "negated condition block" in decision.reason


def test_a_rule_level_or_is_undecided(graph):
    conditions = json.dumps(
        [
            {"operator": "OR", "operands": [{"type": "APP", "rhs": "2001"}]},
            {"operator": "OR", "operands": [{"type": "SCIM_GROUP", "rhs": "7"}]},
        ]
    )
    rule = _scoped(uid="r:1", identity_scope="other", app_scope="other", operator="OR", conditions=conditions)
    graph.access_rules[(IDENTITY, SEGMENT)] = [rule]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate and "joins 2 condition blocks with OR" in decision.reason


def test_require_approval_is_undecided_with_its_reason(graph):
    graph.access_rules[(IDENTITY, SEGMENT)] = [_scoped(uid="r:1", action="require_approval")]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert decision.indeterminate and "require_approval" in decision.reason
    assert "no approval state" in decision.reason


def test_a_row_without_segment_named_reads_as_named(graph):
    graph.access_rules[(IDENTITY, SEGMENT)] = [_rule(uid="r:1", action="allow", app_scope="listed")]
    decision = zpa._access_rule_match(None, IDENTITY, SEGMENT)
    assert (decision.rule["uid"], decision.action) == ("r:1", "allow")


def test_the_access_rule_query_reads_scope_inside_the_segments_tenant():
    query = zpa._ACCESS_RULE_QUERY
    assert "r.app_scope IN ['any', 'other']" in query
    assert "r._scope = seg._scope" in query
    assert "GRANTS|DENIES|APPLIES_TO" in query
    assert "AS segment_named" in query


# --- segment state -----------------------------------------------------------------------------


def test_segment_state_reads_the_segment_and_its_group():
    from hst.core.zpa_policy import segment_state

    assert segment_state(None) == "active"
    assert segment_state({"enabled": True}) == "active"
    assert segment_state({"enabled": False}) == "disabled"
    assert segment_state({"enabled": True, "group_enabled": False}) == "disabled"
    assert segment_state({"bypass_type": "ALWAYS"}) == "bypass"
    assert segment_state({"bypass_type": "on_net"}) == "bypass-on-net"
    assert segment_state({"bypass_type": "NEVER"}) == "active"


def test_the_transition_blocks_a_disabled_segment_and_leaves_a_bypass_undecided(graph, monkeypatch):
    from tests.test_strict_symbolic_gates import TCP

    from hst.path.addrsets import _intervals, _ports
    from hst.path.state import FlowRegion

    region = FlowRegion.from_query(_intervals(["10.0.0.5"]), _intervals(["10.0.20.5"]), TCP, _ports("443"))
    for state, kind in (
        ("disabled", "deny"),
        ("bypass", "indeterminate"),
        ("bypass-on-net", "indeterminate"),
    ):
        monkeypatch.setattr(zpa, "_segment_state", lambda session, uid, s=state: s)
        [(_r, effect)] = zpa.ZpaTransition(None, IDENTITY, SEGMENT).apply(region)
        assert effect.kind == kind, state
        if kind == "deny":
            assert effect.data["blocking_uid"] == SEGMENT


# --- connectors from the groups the winning rule names, one disabled verdict -------------------


def _scripted_reads(monkeypatch, connectors, steering):
    def read(session, query, **params):
        if query is zpa._CONNECTOR_QUERY:
            return connectors
        if query is zpa._RULE_STEERING_QUERY:
            return [{"steering_uid": uid} for uid in steering]
        return []

    monkeypatch.setattr(zpa._path, "_read", read)


def test_a_rule_that_names_one_connector_group_never_selects_a_connector_of_another():
    import pytest

    mp = pytest.MonkeyPatch()
    try:
        rows = [
            {"uid": "c:1", "name": "a", "health": "up", "group_uid": "cg:a"},
            {"uid": "c:2", "name": "b", "health": "up", "group_uid": "cg:b"},
            {"uid": "c:3", "name": "c", "health": "up", "group_uid": "cg:off", "group_enabled": False},
        ]
        _scripted_reads(mp, rows, ["cg:b"])
        selection = zpa._connector_selection(None, SEGMENT, "r:1")
        assert selection.chosen["uid"] == "c:2" and not selection.alternates
        _scripted_reads(mp, rows, [])
        assert [r["uid"] for r in zpa._connector_rows(None, SEGMENT, "r:1")] == ["c:1", "c:2"]
    finally:
        mp.undo()


def test_every_connector_disabled_is_one_deny_in_the_trace_and_the_transition(graph, monkeypatch):
    from tests.test_strict_symbolic_gates import TCP

    from hst.path.addrsets import _intervals, _ports
    from hst.path.state import FlowRegion

    graph.segment_ports[SEGMENT] = {"tcp": ["443", "443"], "udp": None}
    graph.access_rules[(IDENTITY, SEGMENT)] = [
        _rule(uid="r:1", position=1, action="allow", identity_named=True)
    ]
    graph.segment_resolution[SEGMENT] = [{"addr": "10.0.20.5"}]
    graph.zpa_connectors[SEGMENT] = [{"uid": "c:1", "name": "c1", "health": "up", "enabled": False}]
    region = FlowRegion.from_query(_intervals(["10.0.0.5"]), _intervals(["10.0.20.5"]), TCP, _ports("443"))
    for all_connectors in (False, True):
        [(_r, effect)] = zpa.ZpaTransition(None, IDENTITY, SEGMENT, all_connectors=all_connectors).apply(
            region
        )
        assert effect.kind == "deny" and "disabled" in effect.reason, all_connectors


def test_a_connector_with_only_private_ip_gives_a_source_address_and_names_the_basis(monkeypatch):
    def read(session, query, **params):
        return []

    def read_one(session, query, **params):
        return {"private_ip": "10.0.0.9"} if query is zpa._CONNECTOR_PRIVATE_IP_QUERY else None

    monkeypatch.setattr(zpa._path, "_read", read)
    monkeypatch.setattr(zpa._path, "_read_one", read_one)
    address = zpa._connector_address(None, "zpa:acme:conn:6001")
    assert (address.ip, address.basis) == ("10.0.0.9", "private_ip")
