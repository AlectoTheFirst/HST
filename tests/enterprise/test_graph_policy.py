"""Graph policy normalization preserves opaque rule fields as uncertainty."""

from types import MappingProxyType

from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.policy.graph import GraphPolicyNormalizer
from hst.policy.ir import AllOf, Constant, ExecutionContext, Unknown


def _graph():
    rulebase = GraphNode("rb", frozenset({"FwRulebase"}), MappingProxyType({"default_action": "deny"}))
    rule = GraphNode(
        "rule",
        frozenset({"FwRule"}),
        MappingProxyType(
            {
                "position": 10,
                "action": "accept",
                "src_any": True,
                "dst_any": True,
                "svc_any": True,
                "new_vendor_qualifier": "opaque",
            }
        ),
    )
    relation = GraphRelation("has-rule", "HAS_RULE", "rb", "rule", MappingProxyType({}))
    return GraphInventory(
        "a" * 64,
        "fingerprint",
        MappingProxyType({"rb": rulebase, "rule": rule}),
        MappingProxyType({"FwRulebase": ("rb",), "FwRule": ("rule",)}),
        MappingProxyType({("rb", "HAS_RULE"): (relation,)}),
        MappingProxyType({("rule", "HAS_RULE"): (relation,)}),
        True,
        (),
        0,
    )


def test_unknown_raw_rule_property_makes_the_whole_rule_opaque():
    context = ExecutionContext("estate", "authority", "domain", "fw", "vrf", 4)
    policy = GraphPolicyNormalizer(_graph(), context).policy(("rb",), installation=Constant(True))

    predicate = policy.layers[0].rules[0].predicate
    assert isinstance(predicate, AllOf)
    assert Unknown("GRAPH_RULE_UNSUPPORTED_FIELD", "rule", ("new_vendor_qualifier",)) in predicate.terms
