"""Native proposals preserve executable predicates through graph normalization."""

from ipaddress import ip_address
from types import MappingProxyType

from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.native_changes import native_changes
from hst.analysis_model.overlay import _rebuild, apply_overlay
from hst.policy.compile import PolicyCompiler
from hst.policy.graph import GraphPolicyNormalizer
from hst.policy.ir import Constant, ExecutionContext
from hst.symbolic import header

from .test_assessment_symbolic_bridge import native as native


def graph_fixture():
    nodes = {
        "rb": GraphNode("rb", frozenset({"FwRulebase"}), MappingProxyType({"default_action": "deny"})),
        "g": GraphNode("g", frozenset({"NetObject"}), MappingProxyType({"name": "group"})),
        "leaf": GraphNode("leaf", frozenset({"NetObject"}), MappingProxyType({"cidr": "10.0.0.0/24"})),
    }
    relations = [GraphRelation("member", "MEMBER_OF", "leaf", "g", MappingProxyType({}))]
    seed = GraphInventory("a" * 64, "baseline", {}, {}, {}, {}, True, (), 0)
    return _rebuild(seed, nodes, relations)


def added(graph, **changes):
    params = {
        "rulebase": "rb",
        "uid": "r",
        "position": 1,
        "action": "permit",
        "source": ["group", "192.0.2.1-192.0.2.2"],
        "destination": ["any"],
        "protocols": ["tcp", "udp"],
        "ports": ["53", "443"],
        **changes,
    }
    return apply_overlay(graph, native_changes(graph, [{"kind": "fw_rule.add", "params": params}]))


def decision(graph, manager, source, protocol=6, port=443):
    packets = header(
        manager,
        {
            "source_address": int(ip_address(source)),
            "destination_address": int(ip_address("203.0.113.1")),
            "protocol": protocol,
            "destination_port": port,
            "fragment_offset": 0,
        },
    )
    context = ExecutionContext("estate", "authority", "domain", "firewall", "vrf", 4)
    policy = GraphPolicyNormalizer(graph, context).policy(("rb",), installation=Constant(True))
    result = PolicyCompiler(manager, context, packets.known_fields).compile(policy).evaluate(packets)
    assert result.bounds.lower.equivalent(result.bounds.upper), result.gaps
    return not result.bounds.lower.is_empty()


def test_named_group_range_and_service_union_decisions(native):
    graph = added(graph_fixture())
    assert len(graph.targets("r", "SVC")) == 4
    for source in ("10.0.0.1", "10.0.0.255", "192.0.2.1", "192.0.2.2"):
        assert decision(graph, native, source)
        assert decision(graph, native, source, protocol=17, port=53)
    for source in ("10.0.1.1", "192.0.2.0", "192.0.2.3"):
        assert not decision(graph, native, source)
    assert not decision(graph, native, "10.0.0.1", port=80)


def test_modify_service_replaces_predicate_and_disable_can_be_reenabled(native):
    baseline = added(graph_fixture())

    def modify(graph, **params):
        return apply_overlay(
            graph,
            native_changes(
                graph,
                [
                    {
                        "kind": "fw_rule.modify",
                        "params": {"rulebase": "rb", "rule": "r", **params},
                    }
                ],
            ),
        )

    changed = modify(baseline, protocols=["tcp"], ports=["80"])
    assert decision(changed, native, "10.0.0.1", port=80)
    assert not decision(changed, native, "10.0.0.1", port=443)
    assert not decision(changed, native, "10.0.0.1", protocol=17, port=80)
    disabled = modify(changed, enabled=False)
    assert not decision(disabled, native, "10.0.0.1", port=80)
    enabled = modify(disabled, enabled=True)
    assert decision(enabled, native, "10.0.0.1", port=80)
    assert decision(baseline, native, "10.0.0.1", port=443)


def test_separate_additions_keep_rule_membership_and_first_match(native):
    first = added(graph_fixture())
    second = added(first, uid="deny", position=0, action="deny", source=["any"])
    assert {node.uid for node in second.targets("rb", "HAS_RULE")} == {"r", "deny"}
    assert not decision(second, native, "10.0.0.1")
