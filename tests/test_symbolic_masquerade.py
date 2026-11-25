"""A source NAT masquerade in the symbolic model (`policy.nat`, `analysis_model.network`).

A masquerade translates the source to the egress interface's own address and the source
port to one the device picks. The model rewrites the source address to the one address of
the family the egress interface holds, as the point tracer reads it (`_NAT_IFACE_ADDR_QUERY`),
and keeps the packet's own source port. That stands for every port the device can pick only
where nothing after the rule compares the source port; where a state does, the rule's
packets are not decided, and the reason names that state. With no single collected address
the rule stays not decided and names the missing address.

The Oslo office of the demo estate (fixtures/demo-enterprise, `dev:osl01-vyos-01`) is the
owner's shape: zones, a source NAT masquerade on the uplink eth0, a default route to a
provider next hop no collected interface holds. Everything here runs without the native
backend; the walk is in tests/enterprise/test_native_masquerade.py.
"""

from __future__ import annotations

import copy
import importlib
import ipaddress

import pytest
from tests.enterprise import test_network_compile as nc
from tests.test_demo_enterprise_vyos import DEV, MAIN, MASQUERADE, TABLE_100, _estate
from tests.test_symbolic_left_estate import _DemoGraph
from tests.test_symbolic_vyos_service_ports import _inventory

from hst.analysis_model.model import EdgeSpec, NodeSpec, StateKey
from hst.analysis_model.network import _free_source_ports, normalize_network
from hst.impact.evaluate import Interface, Member, Network, RequestSet, Service, member
from hst.path.addrsets import _ports
from hst.policy.ir import AllOf, Atom, Constant, ExecutionContext, Layer, Policy, Rule, Unknown
from hst.policy.nat import normalize_nat_rules
from hst.simul.rib import RibInput

ev = importlib.import_module("hst.impact.evaluate")

ETH0 = f"{DEV}/if/eth0"
WAN = int(ipaddress.ip_address("203.0.113.202"))
LAN_HOST, INTERNET = "10.18.10.21", "192.0.2.180"
# the interfaces of the main table and their connected prefixes and addresses
_CONNECTED = {
    "eth0": ("203.0.113.200/29", "203.0.113.202"),
    "eth1.10": ("10.18.10.0/24", "10.18.10.1"),
    "eth1.20": ("10.18.20.0/24", "10.18.20.1"),
    "eth1.30": ("10.18.30.0/24", "10.18.30.1"),
    "wg0": ("10.18.250.0/30", "10.18.250.2"),
    "wg1": ("10.18.251.0/30", "10.18.251.2"),
}


def oslo_network(batch) -> Network:
    """The Oslo router's IPv4 routing input as its batch states it (the connected
    prefixes, the default route to the provider 203.0.113.201, the static to the
    partner by wg1, policy table 100 by wg0), with the tracer's gates on the batch."""
    return Network(
        RibInput(
            contexts=[
                {"uid": MAIN, "device_uid": DEV, "name": "default", "platform": "vyos"},
                {"uid": TABLE_100, "device_uid": DEV, "name": "table100", "platform": "vyos"},
            ],
            connected=[
                {"context_uid": MAIN, "prefix": prefix, "interface": name}
                for name, (prefix, _address) in _CONNECTED.items()
            ],
            static=[
                {"context_uid": MAIN, "prefix": "0.0.0.0/0", "next_hop": "203.0.113.201"},
                {"context_uid": MAIN, "prefix": "172.20.0.0/16", "interface": "wg1"},
                {"context_uid": TABLE_100, "prefix": "0.0.0.0/0", "interface": "wg0"},
            ],
        ),
        tuple(
            Interface(DEV, f"{DEV}/if/{name}", name, MAIN, (prefix,), (address,))
            for name, (prefix, address) in _CONNECTED.items()
        ),
        ev.GraphGates(_DemoGraph(batch)),
    )


def oslo_request(source=LAN_HOST, destination=INTERNET) -> RequestSet:
    return RequestSet(
        "internet",
        nc._ivals(source),
        "web",
        (Member("web", nc._ivals(destination)),),
        member("web"),
        service=Service(frozenset({6}), tuple(_ports("443"))),
    )


def oslo_model(batch=None, request=None):
    batch = batch if batch is not None else _estate(1)
    request = request or oslo_request()
    return normalize_network(oslo_network(batch), _inventory(batch), request, request.members[0], "estate")


def _without_wan_address(*extra):
    """The estate with eth0's IPv4 address taken away, and `extra` IPv4 addresses added."""
    batch = copy.deepcopy(_estate(1))
    wan = f"ip:vrf-dev-osl01-vyos-01-default:{ipaddress.ip_address(WAN)}"
    batch.rels = [
        r for r in batch.rels if not (r.rel_type == "HAS_IP" and r.start_uid == ETH0 and r.end_uid == wan)
    ]
    template = next(r for r in _estate(1).rels if r.rel_type == "HAS_IP" and r.start_uid == ETH0)
    template_node = next(n for n in batch.nodes if n.uid == wan)
    for address in extra:
        uid = f"ip:test:{address}"
        node = copy.deepcopy(template_node)
        node.uid, node.props = uid, {**node.props, "uid": uid, "ip": address}
        batch.nodes.append(node)
        rel = copy.deepcopy(template)
        rel.end_uid = uid
        batch.rels.append(rel)
    return batch


def _masquerade(batch):
    (spec,) = [
        spec
        for spec in normalize_nat_rules(
            _inventory(batch), DEV, ingress_interface_uid=None, egress_interface_uid=ETH0, address_family=4
        )
        if spec.uid == MASQUERADE
    ]
    return spec


def _nodes(model):
    return {node.key.location: node for node in model.nodes}


# --- the rule -----------------------------------------------------------------------------


def test_the_masquerade_rewrites_the_source_to_the_uplinks_address_and_keeps_the_port_free():
    spec = _masquerade(_estate(1))
    assert spec.gap_code is None
    assert spec.rewrites == (("source_address", WAN),)
    assert spec.ranges == ()
    assert spec.free_source_port is True


def test_with_no_collected_uplink_address_the_masquerade_names_the_missing_address():
    spec = _masquerade(_without_wan_address())
    assert spec.gap_code == "NAT_MASQUERADE_ADDRESS_UNKNOWN"
    assert spec.rewrites == ()
    assert any(isinstance(term, Unknown) and term.code == spec.gap_code for term in spec.predicate.terms)


def test_with_two_uplink_addresses_the_masquerade_is_not_decided():
    spec = _masquerade(_without_wan_address("203.0.113.203", "203.0.113.204"))
    assert spec.gap_code == "NAT_MASQUERADE_ADDRESS_UNKNOWN"


def test_a_masquerade_with_no_resolved_egress_keeps_its_binding_gap():
    (spec,) = [
        spec
        for spec in normalize_nat_rules(
            _inventory(_estate(1)),
            DEV,
            ingress_interface_uid=None,
            egress_interface_uid=None,
            address_family=4,
        )
        if spec.uid == MASQUERADE
    ]
    assert spec.gap_code == "NAT_INTERFACE_BINDING_UNKNOWN"


# --- the Oslo forward model ---------------------------------------------------------------


def test_the_plain_internet_flow_is_translated_at_the_uplink_and_leaves_at_the_edge():
    nodes = _nodes(oslo_model())
    (gate,) = [node for node in nodes.values() if node.key.stage == "snat" and node.edges]
    edge = next(edge for edge in gate.edges if edge.uid == MASQUERADE)
    assert edge.rewrites == (("source_address", WAN),)
    assert not any("Unknown" in repr(term) for term in (edge.predicate,))
    # the rule's packets continue to the estate's edge, not to an unknown terminal
    assert edge.target.location == f"estate-edge-split:{MAIN}:0.0.0.0/0:203.0.113.201"
    assert not any(":unknown:" in location and MASQUERADE in location for location in nodes)
    assert not any(":source-port:" in location for location in nodes)
    assert nodes[f"estate-edge:{MAIN}:0.0.0.0/0:203.0.113.201"].terminal == "permit"
    # the routing state the LAN host enters is complete
    assert nodes[f"routing:{MAIN}:ingress:{DEV}/if/eth1.10"].complete is True


def test_with_no_collected_uplink_address_the_flow_stays_not_decided_at_the_rule():
    nodes = _nodes(oslo_model(_without_wan_address()))
    (gate,) = [node for node in nodes.values() if node.key.stage == "snat" and node.edges]
    edge = next(edge for edge in gate.edges if edge.uid == MASQUERADE)
    assert nodes[edge.target.location].terminal == "unknown"
    assert "NAT_MASQUERADE_ADDRESS_UNKNOWN" in repr(edge.predicate)


# --- nothing after the rule may compare the source port -----------------------------------

CTX = ExecutionContext("estate", "graph", "graph", DEV, MAIN, 4)
GATE = StateKey("gate:r1:snat:next", CTX, "snat")
NEXT = StateKey("next", CTX)
DONE = StateKey("done", CTX)
SPORT = Atom("source_port", "range", 1024, 2047)


def _chain(next_node):
    return [
        NodeSpec(
            GATE,
            (
                EdgeSpec("rule:masquerade", NEXT, Constant(True), (("source_address", WAN),)),
                EdgeSpec("snat:fallthrough", NEXT, Constant(False)),
            ),
        ),
        next_node,
        NodeSpec(DONE, terminal="permit"),
    ]


def _policy(predicate):
    return Policy(
        "p",
        "r",
        CTX,
        (Layer("l", (Rule("x", predicate, "deny"),), "permit"),),
        ("l",),
        installation=Constant(True),
    )


def test_a_later_state_that_reads_no_source_port_keeps_the_rewrite():
    nodes = _chain(NodeSpec(NEXT, (EdgeSpec("go", DONE, Atom("destination_port", "eq", 443)),)))
    out = _free_source_ports(nodes, [(GATE, "rule:masquerade")])
    # the edges are kept, and the gate records the edge for the reply's check
    assert [node.edges for node in out] == [node.edges for node in nodes]
    assert out[0].free_source_ports == ("rule:masquerade",)


def test_a_later_edge_on_the_source_port_leaves_the_rule_not_decided_and_names_it():
    nodes = _chain(NodeSpec(NEXT, (EdgeSpec("go", DONE, SPORT),)))
    out = {node.key.location: node for node in _free_source_ports(nodes, [(GATE, "rule:masquerade")])}
    edge = next(edge for edge in out[GATE.location].edges if edge.uid == "rule:masquerade")
    assert out[edge.target.location].terminal == "unknown"
    assert edge.rewrites == ()
    assert edge.predicate == AllOf((Constant(True), Unknown("NAT_SOURCE_PORT_UNKNOWN", "next")))
    # the packets no rule claims are not touched
    fallthrough = next(edge for edge in out[GATE.location].edges if edge.uid == "snat:fallthrough")
    assert fallthrough.target == NEXT


def test_a_later_policy_on_the_source_port_leaves_the_rule_not_decided():
    nodes = _chain(NodeSpec(NEXT, (EdgeSpec("go", DONE),), policy=_policy(SPORT)))
    out = {node.key.location: node for node in _free_source_ports(nodes, [(GATE, "rule:masquerade")])}
    edge = next(edge for edge in out[GATE.location].edges if edge.uid == "rule:masquerade")
    assert out[edge.target.location].terminal == "unknown"
    assert "NAT_SOURCE_PORT_UNKNOWN" in repr(edge.predicate)


def test_the_unknown_terminal_names_the_state_that_reads_the_port():
    nodes = _chain(NodeSpec(NEXT, (EdgeSpec("go", DONE, SPORT),)))
    out = {node.key.location: node for node in _free_source_ports(nodes, [(GATE, "rule:masquerade")])}
    edge = next(edge for edge in out[GATE.location].edges if edge.uid == "rule:masquerade")
    assert edge.target.location == "gate:r1:snat:next:source-port:rule:masquerade:read-at:next"


def _with_outbound_acl(direction="out"):
    """The estate with an interface ACL bound to eth0 in `direction`, as the
    Cisco and UniFi collectors write one (PROTECTED_BY with a direction)."""
    batch = copy.deepcopy(_estate(1))
    template_node = next(n for n in batch.nodes if n.label == "FwRulebase")
    acl = copy.deepcopy(template_node)
    acl.uid = "acl:test:OUT"
    acl.props = {
        "uid": acl.uid,
        "name": "OUT",
        "kind": "access",
        "vendor": "cisco",
        "match_context": "interface-acl",
    }
    batch.nodes.append(acl)
    rel = copy.deepcopy(next(r for r in batch.rels if r.rel_type == "HAS_IP" and r.start_uid == ETH0))
    rel.rel_type, rel.end_uid, rel.props = "PROTECTED_BY", acl.uid, {"direction": direction}
    batch.rels.append(rel)
    return batch


def test_an_outbound_interface_acl_on_the_uplink_keeps_the_masquerade_not_decided():
    """The device evaluates an outbound interface ACL after the translation
    (the IOS order, the tracer's `_apply_egress_acl`); the model places the
    egress filter before the source NAT, so it would judge the untranslated
    source. The rule stays not decided and says why."""
    assert _masquerade(_with_outbound_acl()).gap_code == "NAT_EGRESS_FILTER_AFTER_TRANSLATION"
    # an inbound list is judged on the arriving packet, before any translation
    assert _masquerade(_with_outbound_acl("in")).gap_code is None


def test_the_owners_vyos_zone_filter_runs_before_the_masquerade_and_stays_decided():
    """VyOS judges its zone rules in the forward hook, before postrouting
    source NAT, where the model places them: the Oslo flow is decided."""
    nodes = _nodes(oslo_model())
    (gate,) = [node for node in nodes.values() if node.key.stage == "snat" and node.edges]
    assert gate.free_source_ports == (MASQUERADE,)
    filters = [node for node in nodes.values() if node.key.location.startswith("egress-filter:")]
    assert filters and all(edge.target == gate.key for node in filters for edge in node.edges)


def test_a_cisco_interface_overload_with_an_outbound_acl_is_never_decided():
    """The rule `ip nat inside source list 7 interface GigabitEthernet1/0/1 overload`
    with `ip access-group MGMT-OUT out` on that interface reaches no decided translation."""
    from tests import test_iosxe as iosxe

    config = iosxe.INTERFACE_CONFIG_TEXT.replace(
        " ip address 10.0.0.1 255.255.255.0\n",
        " ip address 10.0.0.1 255.255.255.0\n ip access-group MGMT-OUT out\n",
        1,
    )
    batch = iosxe._collector().normalize({**iosxe.RAW, iosxe.CMD_INTERFACE_CONFIG: config})
    graph = _inventory(batch)
    names = {n.props.get("name"): n.uid for n in batch.nodes if n.label == "Interface"}
    specs = {
        spec.uid: spec
        for spec in normalize_nat_rules(
            graph,
            iosxe.DEV,
            ingress_interface_uid=names["Vlan10"],
            egress_interface_uid=names["GigabitEthernet1/0/1"],
            address_family=4,
        )
        if spec.stage == "snat"
    }
    overload = specs["iosxe:sw1x:nat:inside-source:3"]
    assert overload.gap_code is not None and not overload.free_source_port and overload.rewrites == ()


@pytest.mark.parametrize(
    "props",
    [{"static": True}, {"translation_port": 8080}, {"approximate": True}],
    ids=["static-interface-nat", "port-mapping", "approximate"],
)
def test_only_a_true_masquerade_takes_the_decided_branch(props):
    batch = copy.deepcopy(_estate(1))
    rule = next(n for n in batch.nodes if n.uid == MASQUERADE)
    rule.props = {**rule.props, **props}
    spec = _masquerade(batch) if not props.get("static") else _static_spec(batch)
    assert spec is None or (spec.gap_code is not None and not spec.free_source_port)


def _static_spec(batch):
    specs = [
        spec
        for spec in normalize_nat_rules(
            _inventory(batch), DEV, ingress_interface_uid=None, egress_interface_uid=ETH0, address_family=4
        )
        if spec.uid == MASQUERADE and spec.stage == "snat"
    ]
    return specs[0] if specs else None


def test_a_reply_state_before_the_masquerading_device_that_reads_the_picked_port_is_not_decided():
    from hst.analysis_model.model import EntrySpec
    from hst.analysis_model.network import _picked_port_replies

    other = ExecutionContext("estate", "graph", "graph", "dev:dc-fw", "vrf:dc", 4)
    first, done = StateKey("routing:dc:ingress:x", other), StateKey("delivery:home", CTX)
    reads = Atom("destination_port", "range", 1024, 65535)
    for predicate, decided in ((reads, False), (Atom("source_port", "eq", 443), True)):
        nodes = {
            first: NodeSpec(first, (EdgeSpec("fib", GATE, predicate),)),
            GATE: NodeSpec(GATE, (EdgeSpec("home", done),)),
            done: NodeSpec(done, terminal="permit"),
        }
        _picked_port_replies(nodes, [EntrySpec(first)], frozenset({CTX}))
        if decided:
            assert nodes[first].edges[0].target == GATE
        else:
            (edge,) = nodes[first].edges
            assert nodes[edge.target].terminal == "unknown"
            assert edge.predicate == AllOf(
                (Constant(True), Unknown("NAT_SOURCE_PORT_UNKNOWN", first.location))
            )
    # a reply that enters the masquerading device first is restored there: untouched
    nodes = {GATE: NodeSpec(GATE, (EdgeSpec("home", done, reads),)), done: NodeSpec(done, terminal="permit")}
    before = dict(nodes)
    _picked_port_replies(nodes, [EntrySpec(GATE)], frozenset({CTX}))
    assert nodes == before


def test_a_stored_compiled_model_takes_its_free_ports_from_its_source():
    from hst.analysis_model.compile import AnalysisModel, CompiledNode, with_estate_exits
    from hst.analysis_model.model import ChoiceAssignment, ModelInput

    stored = AnalysisModel("a" * 64, "fp", None, (CompiledNode(GATE, (), (), True, ()),), (), (), True)  # type: ignore[arg-type]
    source = ModelInput(
        "a" * 64,
        (NodeSpec(GATE, (EdgeSpec("rule:masquerade", NEXT),), free_source_ports=("rule:masquerade",)),),
        (),
        (ChoiceAssignment("only"),),
        True,
    )
    assert with_estate_exits(stored, source).nodes[0].free_source_ports == ("rule:masquerade",)
