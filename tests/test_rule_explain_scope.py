"""explain_rule on the rule shapes the collectors write: interface and zone
scope, a rule that names no service, the loader's bookkeeping properties, the
connection states a global state policy decides, and the one-sentence summary.

The graphs come from the collectors themselves (VyOS through
`tests.support.policy_route_graph`, Cisco through `_acl_batch`) as a loaded
snapshot holds them (`tests.support.batch_inventory`). The tests that compile
a policy need the native backend; the normalizer and scope tests do not.
"""

from __future__ import annotations

import os

import pytest
from tests.support import policy_route_graph as vyos
from tests.support.batch_inventory import inventory
from tests.test_cisco_common import _PERMIT_ANY_ACE, _acl_batch
from tests.twin_tools_fakes import FakeGraph, call, context, install

from hst import symbolic
from hst.assessment import direct, rule_explain
from hst.assessment import service as assessment_service
from hst.assessment.rule_scope import OTHER_INTERFACE, scope_space
from hst.policy.graph import LOCAL_INTERFACE, GraphPolicyNormalizer
from hst.policy.ir import AllOf, Constant, ExecutionContext, Unknown

HOST = vyos.HOST
LAN_WAN = f"vyos:{HOST}:fw:LAN-WAN"
RULE_10 = f"{LAN_WAN}:10"
CONTEXT = ExecutionContext("test", "configuration", "configuration", "rb", "configuration", 4)
STATE_POLICY = {
    "established": {"action": "accept"},
    "related": {"action": "accept"},
    "invalid": {"action": "drop"},
}
SUMMARY = (
    "Rule 10 of LAN-WAN drops every new flow from 192.168.2.45/32 and 192.168.2.70/32 to any "
    "destination on any protocol and port that enters through zone LAN (eth1 or eth1.10) and leaves "
    "through eth2; the global state policy decides established, invalid and related flows before the "
    "rulebase."
)


def _backend():
    if not symbolic.backend_available():
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail("required native backend missing")
        pytest.skip("optional native backend missing")


def _firewall(rulesets, *, zones=None, groups=None, forward=None):
    """A patch that gives the router eth2 and the firewall tree of the arguments."""

    def patch(cfg):
        cfg["interfaces"]["ethernet"]["eth2"] = {"address": ["dhcp"], "description": "WAN2"}
        ipv4 = {"name": rulesets}
        if forward is not None:
            ipv4["forward"] = {"filter": forward}
        cfg["firewall"] = {
            "global-options": {"state-policy": STATE_POLICY},
            "group": {
                "address-group": {"meta-download": {"address": ["192.168.2.45", "192.168.2.70"]}},
                **(groups or {}),
            },
            "ipv4": ipv4,
            "zone": zones
            if zones is not None
            else {
                "LAN": {"member": {"interface": ["eth1", "eth1.10"]}, "default-action": "drop"},
                "WAN": {
                    "member": {"interface": ["eth0", "eth2"]},
                    "default-action": "drop",
                    "from": {"LAN": {"firewall": {"name": "LAN-WAN"}}},
                },
            },
        }

    return patch


RULE_10_SHAPE = {
    "action": "drop",
    "source": {"group": {"address-group": "meta-download"}},
    "outbound-interface": {"name": "eth2"},
}


def _lan_wan(rules=None, **kwargs):
    """The reported router's LAN-WAN zone-pair rulebase: rule 10 drops the
    meta-download group leaving through eth2, default accept."""
    rulesets = {"LAN-WAN": {"default-action": "accept", "rule": rules or {"10": RULE_10_SHAPE}}}
    return inventory(vyos.batch(_firewall(rulesets, **kwargs)))


_ANY = {"enabled": True, "dst_any": True, "svc_any": True}


def _explain(graph, rulebase, rule, **kwargs):
    document = rule_explain.explain(graph, "test", rulebase, rule, 4, limit=1000, **kwargs)
    assert "error" not in document, document
    return document


def _terms(rule):
    predicate = rule.predicate
    return predicate.terms if isinstance(predicate, AllOf) else (predicate,)


def _unknowns(rule):
    return {term.code for term in _terms(rule) if isinstance(term, Unknown)}


def _normalized(graph, rulebase, **kwargs):
    policy = GraphPolicyNormalizer(graph, CONTEXT).policy((rulebase,), installation=Constant(True), **kwargs)
    return {rule.uid: rule for rule in policy.layers[0].rules}


# --- the normalizer ----------------------------------------------------------------------------


def test_the_rule_identity_and_the_loader_bookkeeping_are_not_rule_semantics():
    graph = _lan_wan()
    props = graph.nodes[RULE_10].props
    assert props["rule_uid"] == "LAN-WAN:10" and "collected_at" in props and "carried" in props

    rule = _normalized(graph, LAN_WAN, ingress="eth1", egress="eth2")[RULE_10]

    assert "GRAPH_RULE_UNSUPPORTED_FIELD" not in _unknowns(rule)


def test_a_property_the_normalizer_does_not_know_still_makes_the_rule_opaque():
    graph = _lan_wan()
    node = graph.nodes[RULE_10]
    object.__setattr__(node, "props", {**node.props, "vendor_qualifier": "time-range"})

    rule = _normalized(graph, LAN_WAN, ingress="eth1", egress="eth2")[RULE_10]

    unsupported = [
        term for term in _terms(rule) if getattr(term, "code", "") == "GRAPH_RULE_UNSUPPORTED_FIELD"
    ]
    assert [term.evidence for term in unsupported] == [("vendor_qualifier",)]


def test_a_vyos_rule_that_names_no_service_matches_every_protocol_and_port():
    graph = _lan_wan()
    assert not graph.targets(RULE_10, "SVC") and "svc_any" not in graph.nodes[RULE_10].props

    rule = _normalized(graph, LAN_WAN, ingress="eth1", egress="eth2")[RULE_10]

    assert "GRAPH_RULE_COLUMN_MISSING" not in _unknowns(rule)
    assert _terms(rule)[2] == Constant(True)


def test_a_rule_of_another_vendor_without_a_service_column_keeps_the_gap():
    graph = _lan_wan()
    base = graph.nodes[LAN_WAN]
    object.__setattr__(base, "props", {**base.props, "vendor": "other"})

    rule = _normalized(graph, LAN_WAN, ingress="eth1", egress="eth2")[RULE_10]

    assert "GRAPH_RULE_COLUMN_MISSING" in _unknowns(rule)


@pytest.mark.parametrize(
    ("scope", "egress", "matches"),
    [
        ("eth2", "eth2", True),
        ("eth2", "eth0", False),
        ("eth*", "eth2", True),
        ("eth*", "wg0", False),
        ("!eth0", "eth2", True),
        ("!eth0", "eth0", False),
        ("!eth*", "wg0", True),
        ("eth2", LOCAL_INTERFACE, False),
        ("!eth0", LOCAL_INTERFACE, False),
    ],
)
def test_an_interface_scope_is_a_name_a_wildcard_or_a_negation(scope, egress, matches):
    graph = _lan_wan({"10": {**RULE_10_SHAPE, "outbound-interface": {"name": scope}}})

    rule = _normalized(graph, LAN_WAN, ingress="eth1", egress=egress)[RULE_10]

    assert Constant(matches) in _terms(rule)
    assert "GRAPH_RULE_INTERFACE_UNKNOWN" not in _unknowns(rule)


def test_an_interface_scope_without_the_flow_interface_stays_unknown():
    rule = _normalized(_lan_wan(), LAN_WAN)[RULE_10]

    assert "GRAPH_RULE_INTERFACE_UNKNOWN" in _unknowns(rule)


# --- the scopes --------------------------------------------------------------------------------


def test_a_zone_pair_receives_the_flows_from_its_source_zone_to_its_destination_zone():
    space = scope_space(_lan_wan(), LAN_WAN, RULE_10)

    assert space.gaps == ()
    assert space.entry == {
        "kind": "zone-pair",
        "evaluated": True,
        "from_zone": "LAN",
        "to_zone": "WAN",
        "ingress": ["eth1", "eth1.10"],
        "egress": ["eth0", "eth2"],
        "states": ["new"],
        "state_policy": ["established=accept", "invalid=drop", "related=accept"],
    }
    # eth1 and eth1.10 are alike to every rule; eth2 and eth0 are not to rule 10
    assert [c.members for c in space.ingress] == [("eth1", "eth1.10")]
    assert sorted(c.members for c in space.egress) == [("eth0",), ("eth2",)]
    assert len(space.combinations) == 2


def test_a_zone_without_member_interfaces_leaves_the_entry_unevaluated():
    zones = {
        "LAN": {"default-action": "drop"},
        "WAN": {
            "member": {"interface": ["eth0", "eth2"]},
            "default-action": "drop",
            "from": {"LAN": {"firewall": {"name": "LAN-WAN"}}},
        },
    }

    space = scope_space(_lan_wan(zones=zones), LAN_WAN, RULE_10)

    assert space.gaps == (("GRAPH_ZONE_MEMBERS_MISSING", LAN_WAN),)
    assert space.entry["evaluated"] is False and space.entry["ingress"] is None


def test_a_ruleset_bound_to_two_zone_pairs_has_no_single_pair():
    zones = {
        "LAN": {
            "member": {"interface": ["eth1", "eth1.10"]},
            "default-action": "drop",
            "from": {"WAN": {"firewall": {"name": "LAN-WAN"}}},
        },
        "WAN": {
            "member": {"interface": ["eth0", "eth2"]},
            "default-action": "drop",
            "from": {"LAN": {"firewall": {"name": "LAN-WAN"}}},
        },
    }

    space = scope_space(_lan_wan(zones=zones), LAN_WAN, RULE_10)

    assert ("GRAPH_ZONE_PAIR_UNKNOWN", LAN_WAN) in space.gaps and space.entry["evaluated"] is False


def test_a_local_zone_is_the_router_itself():
    zones = {
        "LAN": {"member": {"interface": ["eth1"]}, "default-action": "drop"},
        "LOCAL": {"local-zone": {}, "from": {"LAN": {"firewall": {"name": "LAN-LOCAL"}}}},
    }
    rulesets = {"LAN-LOCAL": {"default-action": "drop", "rule": {"10": {"action": "accept"}}}}
    graph = inventory(vyos.batch(_firewall(rulesets, zones=zones)))

    space = scope_space(graph, f"vyos:{HOST}:fw:LAN-LOCAL", f"vyos:{HOST}:fw:LAN-LOCAL:10")

    assert space.entry["ingress"] == ["eth1"] and space.entry["egress"] == [LOCAL_INTERFACE]


def test_an_interface_acl_receives_the_flows_of_its_bindings():
    acl = {
        "lists": {"EDGE": [_PERMIT_ANY_ACE]},
        "bindings": [
            {"interface": "Ethernet1/1", "direction": "in", "acl": "EDGE"},
            {"interface": "Vlan10", "direction": "out", "acl": "EDGE"},
        ],
    }
    graph = inventory(_acl_batch(acl))
    (rulebase,) = [
        uid
        for uid in graph.labels["FwRulebase"]
        if graph.nodes[uid].props.get("match_context") == "interface-acl"
    ]
    (rule,) = graph.targets(rulebase, "HAS_RULE")

    space = scope_space(graph, rulebase, rule.uid)

    assert space.entry["inbound"] == ["Ethernet1/1"] and space.entry["outbound"] == ["Vlan10"]
    for i, e, _s in space.combinations:
        ingress, egress = space.ingress[i].members, space.egress[e].members
        assert "Ethernet1/1" in ingress or "Vlan10" in egress


def test_without_the_device_a_wildcard_side_is_not_evaluated_and_a_named_side_has_other():
    from tests.test_twin_tools_assessment import _graph

    scoped = {"out_interface": "eth*", "in_interface": "eth1"}
    graph = _graph([("r1", {"position": 1, "action": "drop", "src_any": True, **_ANY, **scoped}, [])])

    space = scope_space(graph, "rb", "r1")

    assert [c.representative for c in space.egress] == [None]
    assert sorted(c.members for c in space.ingress) == [(OTHER_INTERFACE,), ("eth1",)]


# --- explain_rule ------------------------------------------------------------------------------


def test_the_reported_lan_wan_rule_10_is_definite_on_eth2_for_any_service():
    _backend()

    document = _explain(_lan_wan(), LAN_WAN, RULE_10)

    assert document["action"] == "deny" and document["gaps"] == []
    assert document["possible_empty"] is True and document["lower_empty"] is False
    assert [scope["applies_when"] for scope in document["scopes"]] == [
        [{"ingress": ["eth1", "eth1.10"], "egress": ["eth2"], "states": ["new"]}]
    ]
    definite = [item for item in document["items"] if item["match"] == "definite"]
    assert {tuple(item["sources"]) for item in definite} == {("192.168.2.45/32", "192.168.2.70/32")}
    assert {tuple(item["destinations"]) for item in definite} == {("0.0.0.0/0",)}
    assert rule_explain._any_service(definite)
    assert document["summary"] == SUMMARY


def test_the_reported_rule_is_proven_in_the_tool_envelope(monkeypatch):
    _backend()
    graph = _lan_wan()
    install(monkeypatch, FakeGraph())
    monkeypatch.setattr(
        assessment_service,
        "snapshot_reference",
        lambda settings, value: {
            "snapshot": "4000",
            "manifest_sha256": "a" * 64,
            "estate": "test",
            "observation_floor_ms": None,
        },
    )
    monkeypatch.setattr(
        direct,
        "run_isolated",
        lambda settings, inputs: rule_explain.explain(
            graph,
            "test",
            inputs["rulebase"],
            inputs["rule"],
            4,
            offset=inputs["offset"],
            limit=inputs["limit"],
        ),
    )
    ctx = context(analysis_engine="symbolic-v2")
    ctx.store = None

    failed, envelope = call(
        "policy_evaluate", {"mode": "explain_rule", "rulebase": LAN_WAN, "rule": RULE_10}, ctx
    )

    assert not failed, envelope
    assert envelope["evidence"]["result"]["answer"] == "true" and envelope["evidence"]["gaps"] == []
    result = envelope["result"]
    assert result["match_detail"] == SUMMARY
    assert result["entry"]["from_zone"] == "LAN" and result["entry"]["to_zone"] == "WAN"
    assert result["scopes"][0]["applies_when"][0]["egress"] == ["eth2"]
    assert all(item["scope"] == 0 for item in result["first_match"]) and result["not_decided"] == []
    assert not any("is not evaluated" in unknown for unknown in envelope["evidence"]["unknowns"])


def test_a_rule_scoped_to_an_interface_group_keeps_its_gap():
    _backend()
    rules = {"10": {**RULE_10_SHAPE, "outbound-interface": {"group": "UPLINKS"}}}
    graph = _lan_wan(rules, groups={"interface-group": {"UPLINKS": {"interface": ["eth0", "eth2"]}}})

    document = _explain(graph, LAN_WAN, RULE_10)

    assert document["lower_empty"] is True and document["possible_empty"] is False
    assert {gap["code"] for gap in document["gaps"]} == {"GRAPH_RULE_QUALIFIER_UNKNOWN"}


def test_a_zone_without_members_makes_every_match_possible_only():
    _backend()
    zones = {
        "LAN": {"default-action": "drop"},
        "WAN": {
            "member": {"interface": ["eth0", "eth2"]},
            "default-action": "drop",
            "from": {"LAN": {"firewall": {"name": "LAN-WAN"}}},
        },
    }

    document = _explain(_lan_wan(zones=zones), LAN_WAN, RULE_10)

    assert document["lower_empty"] is True and document["possible_empty"] is False
    assert {gap["code"] for gap in document["gaps"]} >= {"GRAPH_ZONE_MEMBERS_MISSING"}


def test_a_forward_chain_rule_is_scoped_to_its_interfaces():
    _backend()
    forward = {
        "default-action": "accept",
        "rule": {
            "10": {
                "action": "drop",
                "inbound-interface": {"name": "eth1.10"},
                "outbound-interface": {"name": "!eth0"},
            }
        },
    }
    graph = inventory(vyos.batch(_firewall({}, forward=forward)))
    chain = f"vyos:{HOST}:fw:ipv4-forward"

    document = _explain(graph, chain, f"{chain}:10")

    assert document["gaps"] == [] and document["possible_empty"] is True
    (scope,) = document["scopes"]
    (applies,) = scope["applies_when"]
    assert applies["ingress"] == ["eth1.10"] and "eth0" not in applies["egress"]
    assert document["entry"]["kind"] == "chain" and document["entry"]["evaluated"] is True


def test_a_rule_scoped_to_a_state_the_state_policy_decides_matches_nothing_the_rulebase_receives():
    _backend()
    rules = {"10": {"action": "accept", "state": {"established": "enable"}}}

    document = _explain(_lan_wan(rules), LAN_WAN, RULE_10)

    assert document["possible_empty"] is True and document["lower_empty"] is True
    assert document["matches_nothing"] is True and document["gaps"] == []
    assert document["summary"].startswith("Rule 10 of LAN-WAN matches no flow that its rulebase receives")


def test_a_cisco_acl_rule_is_explained_for_its_bindings():
    _backend()
    acl = {
        "lists": {"EDGE": [_PERMIT_ANY_ACE]},
        "bindings": [{"interface": "Ethernet1/1", "direction": "in", "acl": "EDGE"}],
    }
    graph = inventory(_acl_batch(acl))
    (rulebase,) = [
        uid
        for uid in graph.labels["FwRulebase"]
        if graph.nodes[uid].props.get("match_context") == "interface-acl"
    ]
    (rule,) = graph.targets(rulebase, "HAS_RULE")

    document = _explain(graph, rulebase, rule.uid)

    assert document["gaps"] == [] and document["possible_empty"] is True
    assert [applies["ingress"] for scope in document["scopes"] for applies in scope["applies_when"]] == [
        ["Ethernet1/1"]
    ]
    assert "enters through Ethernet1/1" in document["summary"]


def test_a_nat_rulebase_is_refused():
    def patch(cfg):
        cfg["nat"] = {
            "source": {
                "rule": {
                    "100": {
                        "outbound-interface": {"name": "eth0"},
                        "source": {"address": "10.20.0.0/16"},
                        "translation": {"address": "masquerade"},
                    }
                }
            }
        }

    graph = inventory(vyos.batch(patch))
    rulebase = f"vyos:{HOST}:nat:source"

    error = rule_explain.explain(graph, "test", rulebase, f"{rulebase}:100", 4)["error"]

    assert error["code"] == "invalid_argument" and error["field"] == "rulebase"


def test_a_region_too_fragmented_to_list_whole_is_listed_in_part():
    _backend()
    from tests.test_unifi import CLASSIC_RULES, GROUPS, _gw_batch

    graph = inventory(_gw_batch(firewall_rules=CLASSIC_RULES, firewall_groups=GROUPS))
    rulebase = "unifi:default:fw:lan_in"

    document = _explain(graph, rulebase, f"{rulebase}:fr4")

    assert "render_error" not in document and document["listed_in_part"] is True
    (scope,) = document["scopes"]
    assert scope["possible_pieces"] > scope["possible_count"] == rule_explain.MAX_RECTANGLES
    assert document["possible_count"] == len([i for i in document["items"] if i["match"] == "possible"])


# --- the address family and the entry of a rulebase ------------------------------------------

GUARD = f"vyos:{HOST}:fw:GUARD"
LAN_WAN6 = f"vyos:{HOST}:fw:ipv6:LAN-WAN6"


def _dual_family():
    """LAN-WAN (IPv4: rule 5 jumps to GUARD, rule 10 accepts tcp/22 from any
    source) and LAN-WAN6 (IPv6) on the same zone pair, and GUARD, a named
    ruleset that only the jump reaches."""
    zones = {
        "LAN": {"member": {"interface": ["eth1", "eth1.10"]}, "default-action": "drop"},
        "WAN": {
            "member": {"interface": ["eth0", "eth2"]},
            "default-action": "drop",
            "from": {"LAN": {"firewall": {"name": "LAN-WAN", "ipv6-name": "LAN-WAN6"}}},
        },
    }
    rulesets = {
        "LAN-WAN": {
            "default-action": "drop",
            "rule": {
                "5": {"action": "jump", "jump-target": "GUARD"},
                "10": {"action": "accept", "protocol": "tcp", "destination": {"port": "22"}},
            },
        },
        "GUARD": {
            "default-action": "return",
            "rule": {"10": {"action": "drop", "inbound-interface": {"name": "eth1.10"}}},
        },
    }
    ipv6 = {
        "LAN-WAN6": {
            "default-action": "drop",
            "rule": {"10": {"action": "accept", "source": {"address": "2001:db8::/32"}}},
        }
    }

    def patch(cfg):
        _firewall(rulesets, zones=zones)(cfg)
        cfg["firewall"]["ipv6"] = {"name": ipv6}

    return inventory(vyos.batch(patch))


def test_a_rulebase_of_the_other_family_is_refused_not_explained():
    graph = _dual_family()

    for rulebase, family, recorded in ((LAN_WAN6, 4, 6), (LAN_WAN, 6, 4)):
        error = rule_explain.explain(graph, "test", rulebase, f"{rulebase}:10", family)["error"]

        assert error["code"] == "invalid_argument" and error["field"] == "address_family"
        assert f"IPv{recorded} rulebase" in error["message"]


def test_the_family_of_a_rulebase_is_its_af_or_without_af_its_uid():
    from types import SimpleNamespace

    graph = _dual_family()

    assert rule_explain.rulebase_family(graph.nodes[LAN_WAN]) == 4
    assert rule_explain.rulebase_family(graph.nodes[LAN_WAN6]) == 6
    assert rule_explain.rulebase_family(SimpleNamespace(uid=LAN_WAN6, props={})) == 6
    assert rule_explain.rulebase_family(SimpleNamespace(uid=LAN_WAN, props={})) is None
    assert rule_explain.rulebase_family(SimpleNamespace(uid=LAN_WAN, props={"af": None})) is None


def test_without_a_family_the_rule_is_explained_in_the_family_of_its_rulebase():
    _backend()
    graph = _dual_family()

    document = rule_explain.explain(graph, "test", LAN_WAN6, f"{LAN_WAN6}:10", None, limit=1000)

    assert "error" not in document, document
    assert document["address_family"] == 6 and document["lower_empty"] is False
    assert "matches no flow" not in document["summary"]
    assert all(item["sources"] == ["2001:db8::/32"] for item in document["items"])


def test_a_named_ruleset_reached_only_through_a_jump_has_the_entry_gap_and_its_callers():
    graph = _dual_family()

    space = scope_space(graph, GUARD, f"{GUARD}:10")

    assert space.gaps == (("GRAPH_RULEBASE_ENTRY_UNBOUND", GUARD),)
    assert space.entry["kind"] == "unbound" and space.entry["jump_callers"] == [f"{LAN_WAN}:5"]
    # the ruleset a zone pair binds keeps its entry and no gap
    assert scope_space(graph, LAN_WAN, f"{LAN_WAN}:10").gaps == ()


def test_a_rule_of_a_named_ruleset_reached_only_through_a_jump_matches_nothing_definitely():
    _backend()
    graph = _dual_family()

    document = _explain(graph, GUARD, f"{GUARD}:10")

    assert document["definite_count"] == 0 and document["lower_empty"] is True
    assert {"code": "GRAPH_RULEBASE_ENTRY_UNBOUND", "subject": GUARD} in document["gaps"]
    assert "may match flows" in document["summary"]


def test_the_summary_keeps_a_source_port_restriction():
    rect = {
        "sources": ["0.0.0.0/0"],
        "destinations": ["0.0.0.0/0"],
        "protocols": [17],
        "destination_ports": "0-65535",
        "source_ports": "53",
    }

    assert rule_explain._service([rect]) == "udp source port 53"
    assert rule_explain._flows([rect], 4) == "from any source to any destination on udp source port 53"
    assert rule_explain._service([{**rect, "destination_ports": "22", "source_ports": "0-65535"}]) == (
        "udp destination port 22"
    )


def test_a_protocol_without_ports_keeps_its_name_in_the_summary():
    # the validity mask fixes both ports of a protocol without ports to 0
    def rect(protocols):
        return {
            "sources": ["0.0.0.0/0"],
            "destinations": ["0.0.0.0/0"],
            "protocols": protocols,
            "destination_ports": "0",
            "source_ports": "0",
        }

    assert rule_explain._service([rect([1])]) == "icmp"
    assert rule_explain._flows([rect([1])], 4) == "from any source to any destination on icmp"
    assert rule_explain._service([rect([47])]) == "gre"
    assert rule_explain._service([rect([50])]) == "esp"
    # a rectangle that mixes a protocol with ports and one without cannot place its port
    assert rule_explain._service([{**rect([6, 1]), "destination_ports": "0"}]) is None
