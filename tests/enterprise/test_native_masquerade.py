"""The walk over a masquerade and over a scoped routing state, on the Oslo router.

The model side is in tests/test_symbolic_masquerade.py and
tests/test_symbolic_routing_scope.py; these tests compile those models and walk the plain
forward flow (a LAN host to an internet address on tcp 443): it passes where the data
decides it, and stays not decided, with the named reason, where it does not.
"""

import importlib
import ipaddress
import os
from dataclasses import replace

import pytest

from hst.analysis_model.compile import compile_model
from hst.analysis_model.model import ChoiceAssignment, EntrySpec, ModelInput
from hst.impact.symbolic_walk import walk
from hst.symbolic import HeaderSchema, SymbolicManager
from hst.symbolic.predicates import header

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")


def _packets(manager, source="10.18.10.21", destination="192.0.2.180"):
    return header(
        manager,
        {
            "source_address": int(ipaddress.ip_address(source)),
            "destination_address": int(ipaddress.ip_address(destination)),
            "protocol": 6,
            "destination_port": 443,
        },
        explicitly_all=manager.schema.field_names,
    )


def _walk(model, **packet):
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        compiled = compile_model(model, manager, manager.schema.field_names)
        result = walk(compiled, _packets(manager, **packet), request_id="oslo")
        return (
            not result.bounds.lower.is_empty(),
            not result.bounds.upper.is_empty(),
            set(result.gap_refs),
            {t.outcome for c in result.by_choice for t in c.terminal_reaches},
        )


def test_the_plain_internet_flow_passes_through_the_masquerade():
    from tests.test_symbolic_masquerade import oslo_model

    passes, _upper, gaps, outcomes = _walk(oslo_model())
    assert passes
    assert outcomes == {"permit"}
    assert not {gap for gap in gaps if gap.startswith("NAT_")}


def test_with_no_collected_uplink_address_the_flow_is_not_decided_and_names_it():
    from tests.test_symbolic_masquerade import _without_wan_address, oslo_model

    passes, upper, gaps, _outcomes = _walk(oslo_model(_without_wan_address()))
    assert not passes and upper
    assert "NAT_MASQUERADE_ADDRESS_UNKNOWN" in gaps


@pytest.mark.parametrize("reads_port", [False, True])
def test_a_later_source_port_check_keeps_the_masqueraded_flow_not_decided(reads_port):
    from tests.test_symbolic_masquerade import DONE, GATE, NEXT, SPORT, _chain, _free_source_ports

    from hst.analysis_model.model import EdgeSpec, NodeSpec
    from hst.policy.ir import Atom

    predicate = SPORT if reads_port else Atom("destination_port", "eq", 443)
    nodes = _free_source_ports(
        _chain(NodeSpec(NEXT, (EdgeSpec("go", DONE, predicate),))), [(GATE, "rule:masquerade")]
    )
    model = ModelInput("a" * 64, tuple(nodes), (EntrySpec(GATE),), (ChoiceAssignment("only"),), True)
    passes, upper, gaps, _outcomes = _walk(model)
    if reads_port:
        assert not passes and upper
        assert "NAT_SOURCE_PORT_UNKNOWN" in gaps
    else:
        assert passes


@pytest.mark.parametrize(("destination", "decided"), [("192.0.2.180", True), ("192.0.2.10", False)])
def test_a_gap_for_a_prefix_the_flow_never_uses_does_not_hold_it_back(destination, decided):
    from tests.test_symbolic_masquerade import _estate, _inventory, oslo_request
    from tests.test_symbolic_routing_scope import _oslo_mirrored

    from hst.analysis_model.network import normalize_network

    request = oslo_request(destination=destination)
    model = normalize_network(_oslo_mirrored(), _inventory(_estate(1)), request, request.members[0], "estate")
    passes, upper, gaps, _outcomes = _walk(model, destination=destination)
    assert upper
    if decided:
        assert passes and "MODEL_SCOPE_INCOMPLETE" not in gaps
    else:
        assert not passes and "MODEL_SCOPE_INCOMPLETE" in gaps


OSLO = "dev:osl01-vyos-01"


def _with_state_policy(policy):
    """The estate with the Oslo router's global state policy replaced by
    `policy` (None takes it away)."""
    import copy

    from tests.test_symbolic_masquerade import _estate

    batch = copy.deepcopy(_estate(1))
    for node in batch.nodes:
        if node.uid.startswith("vyos:osl01-vyos-01:fw:") and "global_state_policy" in node.props:
            if policy is None:
                node.props = {k: v for k, v in node.props.items() if k != "global_state_policy"}
            else:
                node.props = {**node.props, "global_state_policy": list(policy)}
    return batch


def _round_trip(
    batch=None,
    source="10.18.10.21",
    destination="192.0.2.180",
    success="round-trip",
    proto=6,
    port="443",
    delivered_to=None,
):
    """The reply of a request as an assessment builds it (`member_packets`:
    only the fields the request states), through `network_session_walk`:
    (the reply's result, the reply model's states by location)."""
    from tests.test_symbolic_masquerade import _estate, _inventory, oslo_model, oslo_network, oslo_request

    from hst.analysis_model.network_session import network_session_walk
    from hst.assessment.symbolic_evaluation import member_packets
    from hst.impact.evaluate import Service
    from hst.path.addrsets import _ports

    batch = batch if batch is not None else _estate(1)
    request = replace(
        oslo_request(source, destination),
        success=success,
        service=Service(frozenset({proto}), tuple(_ports(port))),
    )
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        packets = member_packets(manager, request, request.members[0])
        compiled = compile_model(oslo_model(batch, request), manager, packets.known_fields)
        result = network_session_walk(
            oslo_network(batch),
            _inventory(batch),
            request,
            request.members[0],
            manager,
            compiled,
            packets,
            estate="estate",
            request_id="oslo",
            requires_state=success == "session",
        ).reply
        verdict = (
            "passes"
            if result.bounds.upper.subtract(result.bounds.lower).is_empty()
            and result.bounds.lower.equivalent(result.bounds.universe)
            else "fails"
            if result.bounds.upper.is_empty()
            else "not decided"
        )
        reached = {(t.state.location, t.outcome) for c in result.by_choice for t in c.terminal_reaches}
        if delivered_to is None:
            return verdict, reached, set(result.gap_refs)
        from hst.symbolic.predicates import value_range

        value = int(ipaddress.ip_address(delivered_to))
        to = value_range(manager, "destination_address", value, value)
        hit = any(
            not t.packets.intersect(to).is_empty()
            for c in result.by_choice
            for t in c.terminal_reaches
            if t.outcome == "permit"
        )
        return verdict, reached, set(result.gap_refs), hit


def test_the_reply_of_a_masqueraded_flow_is_restored_and_walked_back():
    from tests.test_symbolic_masquerade import (
        MAIN,
        _estate,
        _inventory,
        oslo_model,
        oslo_network,
        oslo_request,
    )

    from hst.analysis_model.network_session import network_session_walk

    batch = _estate(1)
    request = replace(oslo_request(), success="round-trip")
    model = oslo_model(batch, request)
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        compiled = compile_model(model, manager, manager.schema.field_names)
        result = network_session_walk(
            oslo_network(batch),
            _inventory(batch),
            request,
            request.members[0],
            manager,
            compiled,
            _packets(manager),
            estate="estate",
            request_id="oslo",
        ).reply
        assert not result.bounds.lower.is_empty()
        assert result.bounds.upper.subtract(result.bounds.lower).is_empty()
        reached = {(t.state.location, t.outcome) for c in result.by_choice for t in c.terminal_reaches}
        assert reached == {(f"delivery:{MAIN}:10.18.10.0/24", "permit")}


@pytest.mark.parametrize(
    ("success", "proto", "port"), [("round-trip", 6, "443"), ("session", 6, "443"), ("round-trip", 17, "53")]
)
def test_the_reply_of_a_masqueraded_flow_passes_as_an_assessment_asks_it(success, proto, port):
    from tests.test_symbolic_masquerade import MAIN

    verdict, reached, gaps = _round_trip(success=success, proto=proto, port=port)
    assert verdict == "passes"
    assert reached == {(f"delivery:{MAIN}:10.18.10.0/24", "permit")}
    assert not gaps


def test_a_session_where_the_state_policy_drops_invalid_and_established_traffic_fails():
    """`invalid=drop` is the owner's policy and does not touch a reply of an
    established connection (the test above); a policy that drops established
    traffic blocks it at the state policy."""
    from tests.test_symbolic_masquerade import MAIN

    verdict, reached, _gaps = _round_trip(
        _with_state_policy(["established=drop", "invalid=drop", "related=accept"]), success="session"
    )
    assert verdict == "fails"
    eth0 = f"routing:{MAIN}:ingress:{OSLO}/if/eth0"
    assert {outcome for _state, outcome in reached} == {"deny"}
    assert {state for state, _outcome in reached} == {f"egress-filter:{eth0}:1"}


def test_with_no_state_policy_the_zone_rule_set_drops_the_reply():
    """With no global state policy the WAN to LAN zone rule set judges the
    reply on its own rules: none admits it, so its default action drops it at
    the filter the reply passes on its way to the LAN."""
    from tests.test_symbolic_masquerade import MAIN, _inventory

    from hst.analysis_model.network import _state_admission

    batch = _with_state_policy(None)
    assert (
        _state_admission(_inventory(batch), _context(), ("vyos:osl01-vyos-01:fw:WAN-LAN",), "established")
        is None
    )
    verdict, reached, _gaps = _round_trip(batch)
    assert verdict == "fails"
    eth0 = f"routing:{MAIN}:ingress:{OSLO}/if/eth0"
    assert reached == {(f"egress-filter:{eth0}:1", "deny")}
    rule_set = _reply_policy(batch, f"egress-filter:{eth0}:1")
    assert "vyos:osl01-vyos-01:fw:WAN-LAN" in rule_set


def _context():
    from tests.test_symbolic_masquerade import MAIN

    from hst.policy.ir import ExecutionContext

    return ExecutionContext("estate", "graph", "graph", OSLO, MAIN, 4)


def _reply_policy(batch, location):
    """The layer uids of the reply model's policy at `location`."""
    from tests.test_symbolic_masquerade import _inventory, oslo_network, oslo_request

    from hst.analysis_model.network import normalize_reply_network

    request = replace(oslo_request(), success="round-trip")
    edge = _edge_terminal(batch, request)
    model = normalize_reply_network(
        oslo_network(batch), _inventory(batch), request, request.members[0], "estate", (edge,)
    )
    (node,) = [node for node in model.nodes if node.key.location == location]
    return " ".join(layer.uid for layer in node.policy.layers)


def _edge_terminal(batch, request):
    from tests.test_symbolic_masquerade import oslo_model

    (edge,) = [
        node.key for node in oslo_model(batch, request).nodes if node.key.location.startswith("estate-edge:")
    ]
    return edge


def test_a_reply_that_enters_by_another_interface_is_not_the_masquerades_connection():
    """The masquerade translated to eth0's address: its connection is eth0's.
    A reply to that address that enters the router by eth1.20 is not decided
    and names why, never restored and forwarded."""
    from tests.test_symbolic_masquerade import _estate, _inventory, oslo_model, oslo_network, oslo_request

    from hst.analysis_model.network import normalize_reply_network
    from hst.analysis_model.network_session import _interface_addresses, reply_destinations
    from hst.analysis_model.session_walk import session_walk
    from hst.analysis_model.sessions import install_reverse_translations
    from hst.assessment.symbolic_evaluation import member_packets

    batch = _estate(1)
    request = replace(oslo_request(), success="round-trip")
    network = oslo_network(batch)
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        packets = member_packets(manager, request, request.members[0])
        forward = compile_model(oslo_model(batch, request), manager, packets.known_fields)
        preview = walk(forward, packets, request_id="oslo")
        (terminal,) = {
            t.state for c in preview.by_choice for t in c.terminal_reaches if t.outcome == "permit"
        }
        permitted = manager.empty()
        for c in preview.by_choice:
            for t in c.terminal_reaches:
                permitted = permitted.union(t.packets.intersect(c.bounds.lower))
            elsewhere = replace(terminal, binding_scope=(f"reply-ingress:{OSLO}/if/eth1.20",))
        reply_input = normalize_reply_network(
            network,
            _inventory(batch),
            request,
            request.members[0],
            "estate",
            (elsewhere,),
            destinations=reply_destinations(permitted, 4),
        )
        reply = install_reverse_translations(
            forward,
            compile_model(reply_input, manager, packets.known_fields),
            interface_addresses=_interface_addresses(network),
            request=packets,
        )
        result = session_walk(forward, reply, packets, request_id="oslo", forward_result=preview).reply
        assert result.bounds.lower.is_empty()
        assert not result.bounds.upper.is_empty()
        assert "SESSION_REPLY_INGRESS_NOT_TRANSLATING" in result.gap_refs
        reached = {(t.state.location, t.outcome) for c in result.by_choice for t in c.terminal_reaches}
        assert reached == {("session-inverse:unknown:SESSION_REPLY_INGRESS_NOT_TRANSLATING", "unknown")}


def test_a_flow_the_forward_walk_did_not_translate_is_not_mapped_back():
    from tests.test_symbolic_masquerade import MAIN

    verdict, reached, gaps = _round_trip(destination="10.18.20.31")
    assert verdict == "passes"
    assert reached == {(f"delivery:{MAIN}:10.18.10.0/24", "permit")}
    assert not gaps


def test_an_unsolicited_flow_to_the_uplinks_address_takes_the_port_forward():
    from tests.test_symbolic_masquerade import MAIN, oslo_model, oslo_request

    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        model = compile_model(
            oslo_model(None, oslo_request("203.0.113.201", "203.0.113.202")),
            manager,
            manager.schema.field_names,
        )
        result = walk(model, _packets(manager, "203.0.113.201", "203.0.113.202"), request_id="oslo")
        assert result.bounds.upper.subtract(result.bounds.lower).is_empty() and not result.gap_refs
        reached = {(t.state.location, t.outcome) for c in result.by_choice for t in c.terminal_reaches}
        # the NAS 10.18.10.20 is on the LAN segment
        assert reached == {(f"delivery:{MAIN}:10.18.10.0/24", "permit")}
    verdict, reached, gaps = _round_trip(source="203.0.113.201", destination="203.0.113.202")
    assert verdict == "passes"
    assert reached == {(f"delivery:{MAIN}:203.0.113.200/29", "permit")}
    assert not gaps


NS = "vyos:osl01-vyos-01"


def _node(batch, uid):
    return next(node for node in batch.nodes if node.uid == uid)


def _rule(batch, base, template, uid, position, rels, **props):
    """A copy of rule `template` as rule `uid` of rule set `base`, with the
    relations of `rels` ((type, rule they are copied from))."""
    import copy

    new = copy.deepcopy(_node(batch, template))
    new.uid = uid
    new.props = {**new.props, "uid": uid, "position": position, "rule_uid": uid.split(":fw:")[1], **props}
    batch.nodes.append(new)
    has = copy.deepcopy(next(r for r in batch.rels if r.rel_type == "HAS_RULE" and r.end_uid == template))
    has.start_uid, has.end_uid = base, uid
    batch.rels.append(has)
    for rel_type, source_rule in rels:
        rel = copy.deepcopy(
            next(r for r in batch.rels if r.rel_type == rel_type and r.start_uid == source_rule)
        )
        rel.start_uid = uid
        batch.rels.append(rel)


def _port_forward_beside_the_masquerade():
    """No global state policy; the port forward names the uplink's address and
    port 1883 (one address to one); WAN-LAN accepts mqtt to the NAS; LAN-WAN
    drops what the NAS sends; the masquerade is kept."""
    import copy

    batch = _with_state_policy(None)
    dnat = _node(batch, f"{NS}:nat:destination:10")
    dnat.props["orig_dst_port"] = "1883"
    dnat.props["orig_dst"] = "203.0.113.202/32"
    iot_lan = f"{NS}:fw:IOT-LAN:10"
    _rule(batch, f"{NS}:fw:WAN-LAN", iot_lan, f"{NS}:fw:WAN-LAN:77", 77, (("DST", iot_lan), ("SVC", iot_lan)))
    _rule(
        batch,
        f"{NS}:fw:LAN-WAN",
        iot_lan,
        f"{NS}:fw:LAN-WAN:3",
        3,
        (),
        action="drop",
        src_any=False,
        dst_any=True,
        name="nas never out",
    )
    source = copy.deepcopy(next(r for r in batch.rels if r.rel_type == "DST" and r.start_uid == iot_lan))
    source.rel_type, source.start_uid = "SRC", f"{NS}:fw:LAN-WAN:3"
    batch.rels.append(source)
    return batch


def test_a_one_to_one_port_forward_never_rewrites_the_reply_of_a_flow_it_did_not_translate():
    from tests.test_symbolic_masquerade import MAIN

    verdict, reached, _gaps = _round_trip(
        _port_forward_beside_the_masquerade(), source="203.0.113.201", destination="10.18.10.20", port="1883"
    )
    assert verdict == "fails"
    assert reached == {(f"egress-filter:routing:{MAIN}:ingress:{OSLO}/if/eth1.10:2", "deny")}


def test_the_reply_of_an_untranslated_flow_is_a_packet_of_its_connection_and_takes_no_port_forward():
    """The masquerade narrowed to 10.18.10.0/25 leaves 10.18.10.200 untranslated.
    Its reply enters eth0 as a packet of an existing connection, which the
    connection table matches before any NAT rule: none of it is taken to the
    NAS by the port forward (tcp 443), all of it goes back to 10.18.10.200."""
    import copy

    from tests.test_symbolic_masquerade import MAIN, _estate

    batch = copy.deepcopy(_estate(1))
    _node(batch, f"{NS}:nat:source:100").props["orig_src"] = "10.18.10.0/25"
    verdict, reached, gaps, to_nas = _round_trip(batch, source="10.18.10.200", delivered_to="10.18.10.20")
    assert verdict == "passes" and not gaps
    assert reached == {(f"delivery:{MAIN}:10.18.10.0/24", "permit")}
    assert not to_nas


@pytest.mark.parametrize(
    ("variant", "verdict", "code"),
    [
        ({"platform": "iosxe"}, "passes", None),
        ({"platform": "iosxe", "acl": "in"}, "not decided", "SESSION_REPLY_ACL_BEFORE_RESTORE"),
        ({"platform": "nxos"}, "passes", None),
        ({"platform": "nxos", "acl": "in"}, "not decided", "SESSION_REPLY_ACL_BEFORE_RESTORE"),
        ({"platform": "checkpoint"}, "passes", None),
        (
            {"platform": "checkpoint", "state_policy": False},
            "not decided",
            "SESSION_STATE_POLICY_NOT_COLLECTED",
        ),
        ({"platform": "fortigate"}, "not decided", "SESSION_STATE_POLICY_NOT_COLLECTED"),
        ({"platform": "paloalto"}, "not decided", "SESSION_REPLY_ORDER_NOT_ESTABLISHED"),
    ],
)
def test_a_restored_reply_is_decided_only_on_a_platform_the_model_orders_as_the_device(
    variant, verdict, code
):
    """The Oslo masquerade round trip with the router dressed as each platform
    (tests/test_symbolic_reply_order.py). Decided: VyOS (the tests above),
    Cisco IOS-XE and NX-OS with no inbound ACL on the uplink, Check Point with
    its state policy collected. Not decided, by name: an inbound ACL on the
    uplink (the device reads it before undoing the translation), a Check
    Point or FortiGate without a collected state policy, any other platform."""
    from tests.test_symbolic_reply_order import platform_variant

    found, _reached, gaps = _round_trip(platform_variant(**variant))
    assert found == verdict
    if code is None:
        assert not gaps
    else:
        assert code in gaps
