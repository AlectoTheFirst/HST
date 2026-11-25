"""The network model applies a device rulebase with the interfaces a flow uses."""

from __future__ import annotations

from types import MappingProxyType

from tests.enterprise.test_network_compile import _ivals, _network

from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.network import _access_policy, _egress_scoped, normalize_request_network
from hst.analysis_model.overlay import _rebuild
from hst.impact.evaluate import Member, RequestSet, member
from hst.policy.ir import AllOf, Constant, ExecutionContext, Unknown

CONTEXT = ExecutionContext("estate", "configuration", "configuration", "r1", "c1", 4)


def _graph(rule: dict) -> GraphInventory:
    """Router r1 with interfaces lan and wan and one VyOS forward chain whose
    only rule drops every flow under `rule`'s interface scope."""
    props = {"position": 10, "action": "drop", "enabled": True, "src_any": True, "dst_any": True, **rule}
    nodes = {
        "r1": GraphNode("r1", frozenset({"Device"}), MappingProxyType({"hostname": "r1"})),
        "if:r1:lan": GraphNode("if:r1:lan", frozenset({"Interface"}), MappingProxyType({"name": "lan"})),
        "if:r1:wan": GraphNode("if:r1:wan", frozenset({"Interface"}), MappingProxyType({"name": "wan"})),
        "fw": GraphNode(
            "fw",
            frozenset({"FwRulebase"}),
            MappingProxyType(
                {"vendor": "vyos", "kind": "access", "chain": "forward", "default_action": "accept"}
            ),
        ),
        "fw:10": GraphNode("fw:10", frozenset({"FwRule"}), MappingProxyType(props)),
    }
    relations = [
        GraphRelation("on-lan", "ON", "if:r1:lan", "r1", MappingProxyType({})),
        GraphRelation("on-wan", "ON", "if:r1:wan", "r1", MappingProxyType({})),
        GraphRelation("enforces", "ENFORCES", "r1", "fw", MappingProxyType({})),
        GraphRelation("has-rule", "HAS_RULE", "fw", "fw:10", MappingProxyType({})),
    ]
    seed = GraphInventory("a" * 64, "seed", {}, {}, {}, {}, True, (), 0)
    return _rebuild(seed, nodes, relations)


def _interface_terms(policy) -> list:
    (rule,) = policy.layers[0].rules
    terms = rule.predicate.terms if isinstance(rule.predicate, AllOf) else (rule.predicate,)
    # the address and service columns come first; the interface conditions follow
    return [term for term in terms[3:] if isinstance(term, (Constant, Unknown))]


def test_an_inbound_interface_rule_is_decided_by_the_ingress_name():
    graph = _graph({"in_interface": "lan"})

    on_lan = _access_policy(graph, CONTEXT, "r1", "if:r1:lan", None, 4, "new")
    on_wan = _access_policy(graph, CONTEXT, "r1", "if:r1:wan", None, 4, "new")

    assert _interface_terms(on_lan) == [Constant(True)]
    assert _interface_terms(on_wan) == [Constant(False)]


def test_an_outbound_interface_rule_is_decided_by_the_egress_name():
    graph = _graph({"out_interface": "wan"})

    to_wan = _access_policy(graph, CONTEXT, "r1", "if:r1:lan", "if:r1:wan", 4, "new")
    unknown = _access_policy(graph, CONTEXT, "r1", "if:r1:lan", None, 4, "new")

    assert _interface_terms(to_wan) == [Constant(True)]
    assert [term.code for term in _interface_terms(unknown)] == ["GRAPH_RULE_INTERFACE_UNKNOWN"]


def test_only_an_egress_condition_moves_the_policy_onto_the_fib_edges():
    assert _egress_scoped(_graph({"out_interface": "wan"}), CONTEXT, "if:r1:lan", 4) is True
    assert _egress_scoped(_graph({"in_interface": "lan"}), CONTEXT, "if:r1:lan", 4) is False


def test_the_walk_applies_an_outbound_rule_on_the_edge_that_leaves_through_its_interface():
    graph = _graph({"out_interface": "wan"})
    request = RequestSet(
        "web",
        _ivals("10.0.0.10"),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
        source_context="c1",
    )

    model = normalize_request_network(_network(), graph, request, "estate")["server"]

    routing = next(node for node in model.nodes if node.key.location == "routing:c1:ingress:none")
    assert routing.policy is None
    filters = [node for node in model.nodes if node.key.location.startswith("egress-filter:routing:c1:")]
    assert filters and all(node.policy is not None for node in filters)
    # the edge toward 203.0.113.0/24 leaves through wan, so the rule's scope is decided
    decided = [_interface_terms(node.policy) for node in filters]
    assert [Constant(True)] in decided
    assert not any(
        isinstance(term, Unknown) and term.code == "GRAPH_RULE_INTERFACE_UNKNOWN"
        for terms in decided
        for term in terms
    )
