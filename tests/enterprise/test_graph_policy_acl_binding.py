"""A Cisco interface ACL in the graph policy normalization: its rules carry no interface,
and its PROTECTED_BY edges scope every rule."""

from types import MappingProxyType

from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.policy.graph import GraphPolicyNormalizer
from hst.policy.ir import AllOf, AnyOf, Constant, ExecutionContext, Unknown

CONTEXT = ExecutionContext("estate", "authority", "domain", "fw", "vrf", 4)


def _graph(
    bindings: list[tuple[str, str]],
    match_context: str = "interface-acl",
    rulebase_props: dict | None = None,
    rule_props: dict | None = None,
) -> GraphInventory:
    nodes = {
        "rb": GraphNode(
            "rb",
            frozenset({"FwRulebase"}),
            MappingProxyType(
                {"default_action": "deny", "match_context": match_context, **(rulebase_props or {})}
            ),
        ),
        "rule": GraphNode(
            "rule",
            frozenset({"FwRule"}),
            MappingProxyType(
                {
                    "position": 1,
                    "action": "permit",
                    "src_any": True,
                    "dst_any": True,
                    "svc_any": True,
                    **(rule_props or {}),
                }
            ),
        ),
    }
    has_rule = GraphRelation("has-rule", "HAS_RULE", "rb", "rule", MappingProxyType({}))
    outgoing: dict = {("rb", "HAS_RULE"): (has_rule,)}
    incoming: dict = {("rule", "HAS_RULE"): (has_rule,)}
    protected = []
    for name, direction in bindings:
        if_uid = f"if:{name}"
        nodes[if_uid] = GraphNode(if_uid, frozenset({"Interface"}), MappingProxyType({"name": name}))
        rel = GraphRelation(
            f"pb:{name}:{direction}", "PROTECTED_BY", if_uid, "rb", MappingProxyType({"direction": direction})
        )
        protected.append(rel)
        outgoing[(if_uid, "PROTECTED_BY")] = (*outgoing.get((if_uid, "PROTECTED_BY"), ()), rel)
    incoming[("rb", "PROTECTED_BY")] = tuple(protected)
    labels: dict = {}
    for uid, node in nodes.items():
        for label in node.labels:
            labels[label] = (*labels.get(label, ()), uid)
    return GraphInventory(
        "a" * 64,
        "fingerprint",
        MappingProxyType(nodes),
        MappingProxyType(labels),
        MappingProxyType(outgoing),
        MappingProxyType(incoming),
        True,
        (),
        0,
    )


def _scope(graph: GraphInventory, ingress: str | None, egress: str | None):
    policy = GraphPolicyNormalizer(graph, CONTEXT).policy(
        ("rb",), installation=Constant(True), ingress=ingress, egress=egress
    )
    predicate = policy.layers[0].rules[0].predicate
    assert isinstance(predicate, AllOf)
    scopes = [term for term in predicate.terms if isinstance(term, AnyOf) or term == Constant(False)]
    assert len(scopes) == 1
    return scopes[0]


SHARED = [("Gi1", "in"), ("Gi2", "in"), ("Gi3", "in")]


def test_a_list_bound_to_several_interfaces_scopes_its_rules_to_each_of_them():
    for ingress in ("Gi1", "Gi2", "Gi3"):
        assert Constant(True) in _scope(_graph(SHARED), ingress, "Gi9").terms
    assert set(_scope(_graph(SHARED), "Gi9", "Gi1").terms) == {Constant(False)}


def test_a_binding_scopes_only_its_own_direction():
    graph = _graph([("Gi1", "in"), ("Gi1", "out")])
    assert _scope(graph, "Gi1", "Gi2").terms == (Constant(True), Constant(False))
    assert _scope(graph, "Gi2", "Gi1").terms == (Constant(False), Constant(True))
    assert set(_scope(graph, "Gi2", "Gi3").terms) == {Constant(False)}


def test_an_unobserved_side_is_unknown_not_a_miss():
    graph = _graph([("Gi1", "out")])
    assert _scope(graph, "Gi1", None).terms == (Unknown("GRAPH_RULE_INTERFACE_UNKNOWN", "rb"),)


def test_a_list_with_no_binding_edge_is_bound_to_nothing():
    assert _scope(_graph([]), "Gi1", "Gi2") == Constant(False)


def test_a_rulebase_that_is_not_an_interface_acl_takes_no_binding_scope():
    policy = GraphPolicyNormalizer(_graph(SHARED, match_context="device"), CONTEXT).policy(
        ("rb",), installation=Constant(True), ingress="Gi9"
    )
    predicate = policy.layers[0].rules[0].predicate
    assert isinstance(predicate, AllOf)
    assert not [term for term in predicate.terms if isinstance(term, AnyOf) or term == Constant(False)]


def _terms(graph: GraphInventory, ingress: str | None, egress: str | None = None):
    policy = GraphPolicyNormalizer(graph, CONTEXT).policy(
        ("rb",), installation=Constant(True), ingress=ingress, egress=egress
    )
    predicate = policy.layers[0].rules[0].predicate
    assert isinstance(predicate, AllOf)
    return predicate.terms


def test_an_unreported_binding_scopes_the_rules_by_its_name():
    graph = _graph([], rulebase_props={"unreported_bindings": ["GigabitEthernet9/9/9 in"]})
    assert _scope(graph, "Gi1", "Gi2").terms == (Constant(False),)
    assert _scope(graph, "GigabitEthernet9/9/9", None).terms == (Constant(True),)
    assert _scope(graph, None, "Gi2").terms == (Unknown("GRAPH_RULE_INTERFACE_UNKNOWN", "rb"),)


def test_a_rulebase_without_a_binding_edge_keeps_the_interface_scope_its_rules_carry():
    graph = _graph([], rule_props={"in_interface": "Gi1"})
    on, off = _terms(graph, "Gi1"), _terms(graph, "Gi2")
    assert not [t for t in on + off if isinstance(t, AnyOf)]
    assert Constant(True) in on and Constant(False) not in on
    assert Constant(False) in off
    assert Unknown("GRAPH_RULE_INTERFACE_UNKNOWN", "rule") in _terms(graph, None)
