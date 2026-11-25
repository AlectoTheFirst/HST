"""The reverse of each forward translation for a reply (`sessions.install_reverse_translations`)."""

import importlib
import ipaddress
import os

import pytest

from hst.analysis_model.compile import compile_model
from hst.analysis_model.model import (
    ChoiceAssignment,
    EdgeSpec,
    EntrySpec,
    ModelInput,
    NodeSpec,
    RangeRewriteSpec,
    StateKey,
)
from hst.analysis_model.session_walk import session_walk
from hst.analysis_model.sessions import install_reverse_translations
from hst.impact.symbolic_walk import walk
from hst.policy.ir import Atom, Constant, ExecutionContext, Not
from hst.symbolic import HeaderSchema, SymbolicManager, header
from hst.symbolic.predicates import ValueRange

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")


def _ip(text):
    return int(ipaddress.ip_address(text))


def _net(text):
    network = ipaddress.ip_network(text)
    return int(network.network_address), int(network.broadcast_address)


R1 = ExecutionContext("estate", "graph", "graph", "dev:r1", "vrf:r1", 4)
R2 = ExecutionContext("estate", "graph", "graph", "dev:r2", "vrf:r2", 4)
SERVER = "192.0.2.1"
HIDE = "203.0.113.5"
MIDDLE = "198.51.100.9"


def _src(predicate_net):
    low, high = _net(predicate_net)
    return Atom("source_address", "range", low, high)


def _dst(net):
    low, high = _net(net)
    return Atom("destination_address", "range", low, high)


def _forward(stage="snat", rewrite=None, ranges=(), chained=False):
    """Forward: the source NAT gate of r1 (and of r2 after it, `chained`), then the edge."""
    edge = StateKey("edge", R2 if chained else R1)
    gate = StateKey("gate:r1:nat", R1, stage)
    after = StateKey("gate:r2:nat", R2, "snat") if chained else edge
    nodes = [
        NodeSpec(
            gate,
            (
                EdgeSpec("rule", after, _src("10.0.0.0/24"), rewrite or (), ranges=ranges),
                EdgeSpec(f"{stage}:fallthrough", after, Not(_src("10.0.0.0/24"))),
            ),
        ),
        NodeSpec(edge, terminal="permit"),
    ]
    if chained:
        nodes.append(
            NodeSpec(
                after,
                (
                    EdgeSpec("rule", edge, _src(f"{MIDDLE}/32"), (("source_address", _ip(HIDE)),)),
                    EdgeSpec("snat:fallthrough", edge, Not(_src(f"{MIDDLE}/32"))),
                ),
            )
        )
    return ModelInput("a" * 64, tuple(nodes), (EntrySpec(gate),), (ChoiceAssignment("only"),), True)


def _reply(chained=False):
    """Reply: r1's routing state by `uplink` sends 10.0.0.0/25 to a permit,
    10.0.0.128/25 to a deny and anything else to an unknown terminal."""
    r1 = StateKey("routing:vrf:r1:ingress:uplink", R1)
    lower, upper, other = StateKey("lan-lower", R1), StateKey("lan-upper", R1), StateKey("other", R1)
    nodes = [
        NodeSpec(
            r1,
            (
                EdgeSpec("lower", lower, _dst("10.0.0.0/25")),
                EdgeSpec("upper", upper, _dst("10.0.0.128/25")),
                EdgeSpec("else", other, Not(_dst("10.0.0.0/24"))),
            ),
        ),
        NodeSpec(lower, terminal="permit"),
        NodeSpec(upper, terminal="deny"),
        NodeSpec(other, terminal="unknown", complete=False),
    ]
    entry = r1
    if chained:
        r2 = StateKey("routing:vrf:r2:ingress:uplink", R2)
        nodes.append(NodeSpec(r2, (EdgeSpec("to-r1", r1, Constant(True)),)))
        entry = r2
    return ModelInput("a" * 64, tuple(nodes), (EntrySpec(entry),), (ChoiceAssignment("only"),), True)


def _round_trip(forward_input, reply_input, source="10.0.0.0/25", binding_required=frozenset()):
    low, high = _net(source)
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        request = header(
            manager,
            {
                "source_address": [ValueRange(low, high)],
                "destination_address": [ValueRange(_ip(SERVER), _ip(SERVER))],
                "protocol": [6],
                "destination_port": [ValueRange(443, 443)],
            },
        )
        forward = compile_model(forward_input, manager, request.known_fields)
        preview = walk(forward, request, request_id="t")
        assert preview.bounds.upper.subtract(preview.bounds.lower).is_empty()
        reply = install_reverse_translations(
            forward,
            compile_model(reply_input, manager, request.known_fields),
            request=request,
            binding_required=binding_required,
        )
        result = session_walk(forward, reply, request, request_id="t", forward_result=preview).reply
        bounds = result.bounds
        verdict = (
            "passes"
            if bounds.upper.subtract(bounds.lower).is_empty() and bounds.lower.equivalent(bounds.universe)
            else "fails"
            if bounds.upper.is_empty()
            else "not decided"
        )
        reached = {(t.state.location, t.outcome) for c in result.by_choice for t in c.terminal_reaches}
        return verdict, reached, set(result.gap_refs)


def test_a_hide_nat_to_one_address_is_restored_to_the_requests_own_source():
    """A Check Point hide NAT or a Cisco overload to one address: the reply to
    that address is restored to the request's own /25, not to any address of
    the rule's /24 (which would reach the deny of the upper half)."""
    verdict, reached, gaps = _round_trip(_forward(rewrite=(("source_address", _ip(HIDE)),)), _reply())
    assert verdict == "passes", (reached, gaps)
    assert reached == {("lan-lower", "permit")}


def test_a_hide_nat_of_a_vsx_virtual_system_waits_for_an_observed_binding():
    """In a VSX virtual system a hide NAT's reply is undone only by an
    observed runtime binding: without one it is not decided and says so."""
    verdict, _reached, gaps = _round_trip(
        _forward(rewrite=(("source_address", _ip(HIDE)),)), _reply(), binding_required=frozenset({"dev:r1"})
    )
    assert verdict == "not decided"
    assert "NAT_BINDING_NOT_OBSERVED" in gaps


def test_a_static_range_nat_is_restored_by_its_offset():
    low, high = _net("10.0.0.0/24")
    ranges = (RangeRewriteSpec("source_address", low, high, _net("198.51.100.0/24")[0]),)
    verdict, reached, _gaps = _round_trip(_forward(ranges=ranges), _reply())
    assert verdict == "passes"
    assert reached == {("lan-lower", "permit")}


def test_a_source_rewritten_twice_on_the_way_is_not_decided():
    """r1 hides the LAN behind one address, r2 hides that behind another: the
    value r2 restores is r1's output, not the request's own source, which
    the reply does not carry. Not decided, with the reason."""
    verdict, _reached, gaps = _round_trip(
        _forward(rewrite=(("source_address", _ip(MIDDLE)),), chained=True), _reply(chained=True)
    )
    assert verdict == "not decided"
    assert "SESSION_REVERSE_TRANSLATION_AMBIGUOUS" in gaps


def test_a_load_balancer_source_rewrite_is_not_decided():
    """A load balancer keeps no connection table the tracer reads (its undo is
    never confident): its many-to-one source rewrite is not decided."""
    verdict, _reached, gaps = _round_trip(
        _forward(stage="load-balancer", rewrite=(("source_address", _ip(HIDE)),)), _reply()
    )
    assert verdict == "not decided"
    assert "SESSION_REVERSE_TRANSLATION_AMBIGUOUS" in gaps


def test_a_source_set_too_wide_to_pin_is_not_decided():
    """Past `MAX_RESTORED_VALUES` sources the pin is not built: not decided,
    with the reason, never restored to a guess."""
    forward = _forward(rewrite=(("source_address", _ip(HIDE)),))
    forward = ModelInput(
        forward.manifest_digest,
        tuple(
            NodeSpec(
                node.key,
                tuple(
                    EdgeSpec(edge.uid, edge.target, _src("10.0.0.0/8"), edge.rewrites)
                    if edge.uid == "rule"
                    else edge
                    for edge in node.edges
                ),
            )
            if node.edges
            else node
            for node in forward.nodes
        ),
        forward.entries,
        forward.choices,
        True,
    )
    verdict, _reached, gaps = _round_trip(forward, _reply(), source="10.0.0.0/16")
    assert verdict == "not decided"
    assert "SESSION_REVERSE_TRANSLATION_TOO_WIDE" in gaps


UPLINK_A, UPLINK_B = "203.0.113.5", "198.51.100.77"


def _two_uplinks(b_translates_to=UPLINK_B):
    """Forward: r1 picks uplink a or b (an equal-cost choice); each uplink's
    source NAT gate masquerades to its own address (uplink b to
    `b_translates_to`) and the flow leaves at that uplink's estate edge.
    Reply: one routing state per uplink, each with the LAN's halves."""
    choices = (ChoiceAssignment("a", (("ecmp", "a"),)), ChoiceAssignment("b", (("ecmp", "b"),)))
    entry = StateKey("routing:vrf:r1:ingress:lan", R1)
    nodes = [
        NodeSpec(
            entry,
            (
                EdgeSpec("via-a", StateKey("gate:a", R1, "snat"), choices=(("ecmp", "a"),)),
                EdgeSpec("via-b", StateKey("gate:b", R1, "snat"), choices=(("ecmp", "b"),)),
            ),
        )
    ]
    edges = {}
    for name, address in (("a", UPLINK_A), ("b", b_translates_to)):
        edge = StateKey(f"edge-{name}", R1, binding_scope=(f"reply-ingress:up{name}",))
        edges[name] = edge
        nodes += [
            NodeSpec(
                StateKey(f"gate:{name}", R1, "snat"),
                (
                    EdgeSpec("rule", edge, _src("10.0.0.0/24"), (("source_address", _ip(address)),)),
                    EdgeSpec("snat:fallthrough", edge, Not(_src("10.0.0.0/24"))),
                ),
                free_source_ports=("rule",),
            ),
            NodeSpec(edge, terminal="permit"),
        ]
    forward = ModelInput("a" * 64, tuple(nodes), (EntrySpec(entry),), choices, True)
    lower, upper, other = StateKey("lan-lower", R1), StateKey("lan-upper", R1), StateKey("other", R1)
    reply_nodes = [
        NodeSpec(lower, terminal="permit"),
        NodeSpec(upper, terminal="deny"),
        NodeSpec(other, terminal="unknown", complete=False),
    ]
    reply_entries = []
    for name in ("a", "b"):
        routing = StateKey(f"routing:vrf:r1:ingress:up{name}", R1)
        reply_nodes.append(
            NodeSpec(
                routing,
                (
                    EdgeSpec("lower", lower, _dst("10.0.0.0/25")),
                    EdgeSpec("upper", upper, _dst("10.0.0.128/25")),
                    EdgeSpec("else", other, Not(_dst("10.0.0.0/24"))),
                ),
            )
        )
        reply_entries.append(EntrySpec(routing))
    reply = ModelInput("a" * 64, tuple(reply_nodes), tuple(reply_entries), (ChoiceAssignment("only"),), True)
    return forward, reply, (edges["a"], edges["b"])


def _walk_two_uplinks(b_translates_to=UPLINK_B):
    low, high = _net("10.0.0.0/25")
    addresses = {"upa": ((4, _ip(UPLINK_A), _ip(UPLINK_A)),), "upb": ((4, _ip(UPLINK_B), _ip(UPLINK_B)),)}
    forward_input, reply_input, terminals = _two_uplinks(b_translates_to)
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        request = header(
            manager,
            {
                "source_address": [ValueRange(low, high)],
                "destination_address": [ValueRange(_ip(SERVER), _ip(SERVER))],
                "protocol": [6],
                "destination_port": [ValueRange(443, 443)],
            },
        )
        forward = compile_model(forward_input, manager, request.known_fields)
        preview = walk(forward, request, request_id="t")
        reply = install_reverse_translations(
            forward,
            compile_model(reply_input, manager, request.known_fields),
            interface_addresses={"vrf:r1": addresses},
            request=request,
        )
        result = session_walk(
            forward,
            reply,
            request,
            request_id="t",
            forward_result=preview,
            entry_terminals=terminals,
            edge_sources=addresses,
        ).reply
        bounds = result.bounds
        verdict = (
            "passes"
            if bounds.upper.subtract(bounds.lower).is_empty() and bounds.lower.equivalent(bounds.universe)
            else "fails"
            if bounds.upper.is_empty()
            else "not decided"
        )
        by_choice = {
            c.assignment.uid: {(t.state.location, t.outcome) for t in c.terminal_reaches}
            for c in result.by_choice
        }
        return verdict, by_choice, set(result.gap_refs)


def test_two_uplinks_each_with_its_own_masquerade_walk_each_reply_from_its_own_uplink():
    """Each forward choice leaves by one uplink and is masqueraded to that
    uplink's address: its reply is walked only from that uplink's entry (the
    forward packets' source is the uplink's own address, so the outside
    returns it there) and restored by that uplink's masquerade."""
    verdict, by_choice, gaps = _walk_two_uplinks()
    assert verdict == "passes" and not gaps
    assert by_choice == {"a": {("lan-lower", "permit")}, "b": {("lan-lower", "permit")}}


def test_a_masquerade_to_the_other_uplinks_address_is_not_that_uplinks_connection():
    """Uplink b translating to uplink a's address: the outside returns that
    reply to a's address, it enters by b in the model, and b's masquerade
    holds no such connection there: not decided, by name."""
    verdict, _by_choice, gaps = _walk_two_uplinks(b_translates_to=UPLINK_A)
    assert verdict == "not decided"
    assert "SESSION_REPLY_INGRESS_NOT_TRANSLATING" in gaps
