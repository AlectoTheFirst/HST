"""A Cisco interface ACL in the graph policy normalization: its rules carry no interface,
and its PROTECTED_BY edges scope every rule. A device binds only the lists that are bound on
an interface of the flow."""

from types import MappingProxyType

from tests.support.batch_inventory import inventory
from tests.test_cisco_common import _PERMIT_ANY_ACE, _acl_batch

from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.network import _access_policy, _bindings, _context
from hst.policy.graph import GraphPolicyNormalizer, acl_governs
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


def _governs(graph: GraphInventory, ingress: str | None, egress: str | None) -> bool | None:
    return acl_governs(graph, graph.nodes["rb"], ingress, egress)


def test_a_list_governs_a_hop_that_uses_a_bound_interface_on_the_side_of_the_binding():
    graph = _graph([("Gi1", "in"), ("Gi2", "out")])
    assert _governs(graph, "Gi1", "Gi9") is True
    assert _governs(graph, "Gi9", "Gi2") is True
    assert _governs(graph, "Gi1", None) is True


def test_a_list_does_not_govern_a_hop_that_uses_other_interfaces():
    graph = _graph([("Gi1", "in"), ("Gi2", "out")])
    assert _governs(graph, "Gi2", "Gi1") is False
    assert _governs(_graph([]), "Gi1", "Gi2") is False
    unreported = _graph([], rulebase_props={"unreported_bindings": ["GigabitEthernet9/9/9 in"]})
    assert _governs(unreported, "Gi1", "Gi2") is False


def test_a_hop_with_no_interface_on_the_side_of_a_binding_leaves_the_list_undecided():
    graph = _graph([("Gi1", "in"), ("Gi2", "out")])
    assert _governs(graph, None, "Gi9") is None
    assert _governs(graph, "Gi9", None) is None


def test_a_list_with_no_binding_edge_governs_by_the_interface_of_its_rules():
    graph = _graph([], rule_props={"in_interface": "Gi1"})
    assert _governs(graph, "Gi1", None) is True
    assert _governs(graph, "Gi2", None) is False
    assert _governs(graph, None, "Gi2") is None


DEVICE, VRF = "dev:sw1", "vrf:dev:sw1:default"
ETH, VLAN = "dev:sw1/if/eth1-1", "dev:sw1/if/vlan10"
_DENY_ANY_ACE = {**_PERMIT_ANY_ACE, "action": "deny"}


def _device(lists: dict[str, list[dict]], bindings: list[tuple[str, str, str]], role: str = "switch"):
    batch = _acl_batch(
        {
            "lists": lists,
            "bindings": [
                {"interface": interface, "direction": direction, "acl": name}
                for name, interface, direction in bindings
            ],
        }
    )
    next(node for node in batch.nodes if node.label == "Device").props["role"] = role
    graph = inventory(batch)
    return graph, _context({}, graph, VRF, "estate", 4, DEVICE)


def _uid(graph: GraphInventory, name: str) -> str:
    return next(uid for uid in graph.labels["FwRulebase"] if graph.nodes[uid].props["name"] == name)


def test_a_list_bound_inbound_on_another_interface_gives_the_flow_no_policy():
    graph, context = _device({"EDGE": [_DENY_ANY_ACE]}, [("EDGE", "Vlan10", "in")])
    assert _bindings(graph, context, ETH, None, 4)[0] == ()
    assert _access_policy(graph, context, DEVICE, ETH, None, 4, "new") is None
    assert _access_policy(graph, context, DEVICE, ETH, VLAN, 4, "new") is None


def test_a_firewall_with_a_list_on_another_interface_has_the_policy_of_a_firewall_with_no_list():
    graph, context = _device({"EDGE": [_DENY_ANY_ACE]}, [("EDGE", "Vlan10", "in")], role="firewall")
    bare, bare_context = _device({}, [], role="firewall")
    policy = _access_policy(graph, context, DEVICE, ETH, None, 4, "new")
    expected = _access_policy(bare, bare_context, DEVICE, ETH, None, 4, "new")
    assert (policy.layers, policy.installation) == (expected.layers, expected.installation)
    assert policy.installation == Unknown("INSTALLATION_UNKNOWN", DEVICE)


def test_the_policy_of_a_flow_holds_only_the_list_of_its_ingress():
    graph, context = _device(
        {"EDGE": [_PERMIT_ANY_ACE], "SERVERS": [_DENY_ANY_ACE]},
        [("EDGE", "Ethernet1/1", "in"), ("SERVERS", "Vlan10", "in")],
    )
    policy = _access_policy(graph, context, DEVICE, ETH, None, 4, "new")
    assert policy.ordered_layers == (_uid(graph, "EDGE"),)
    assert policy.installation == Constant(True)
    policy = _access_policy(graph, context, DEVICE, VLAN, None, 4, "new")
    assert policy.ordered_layers == (_uid(graph, "SERVERS"),)


def test_an_outbound_list_is_bound_for_the_flow_that_leaves_by_its_interface():
    graph, context = _device({"EDGE": [_PERMIT_ANY_ACE]}, [("EDGE", "Vlan10", "out")])
    edge = _uid(graph, "EDGE")
    assert _bindings(graph, context, ETH, VLAN, 4) == ((edge,), Constant(True))
    assert _bindings(graph, context, VLAN, ETH, 4)[0] == ()


def test_the_default_action_of_an_outbound_list_is_unknown_for_a_flow_with_no_egress():
    graph, context = _device({"EDGE": [_PERMIT_ANY_ACE]}, [("EDGE", "Vlan10", "out")])
    edge = _uid(graph, "EDGE")
    assert _bindings(graph, context, ETH, None, 4) == ((edge,), Constant(True))
    (layer,) = _access_policy(graph, context, DEVICE, ETH, None, 4, "new").layers
    assert layer.default == "unknown"
    (layer,) = _access_policy(graph, context, DEVICE, ETH, VLAN, 4, "new").layers
    assert layer.default == "deny"
