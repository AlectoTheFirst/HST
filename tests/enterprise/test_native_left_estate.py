"""The walk carries a terminal's `left_estate` onto its records and changes nothing else.

`NodeSpec.left_estate` (set by the routing node builder where a route leaves the estate at its
edge, tests/test_symbolic_left_estate.py) rides through `compile_model` onto `TerminalReach`
and `WalkGap`; the bounds, the outcomes and the gap codes equal those of the same model with
no object.
"""

import importlib
import ipaddress
import os

import pytest

from hst.analysis_model.compile import compile_model
from hst.analysis_model.model import ChoiceAssignment, EdgeSpec, EntrySpec, ModelInput, NodeSpec, StateKey
from hst.impact.symbolic_walk import walk
from hst.policy.ir import ExecutionContext
from hst.symbolic import HeaderSchema, SymbolicManager
from hst.symbolic.predicates import header

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")

CTX = ExecutionContext("estate", "authority", "domain", "dev:r1", "vrf:r1", 4)
ROUTING = StateKey("routing:vrf:r1:ingress:none", CTX)
EDGE = StateKey("terminal:unknown-hop:vrf:r1:0.0.0.0/0", CTX)
DELIVERY = StateKey("delivery:vrf:r1:0.0.0.0/0", CTX, binding_scope=("reply-ingress:if:r1-eth3",))
EXIT = (
    (
        ("basis", "site-zone"),
        ("device_uid", "dev:r1"),
        ("device", "r1"),
        ("interface_uid", "if:r1-eth3"),
        ("interface", "eth3"),
        ("next_hop", "192.0.2.2"),
        ("wan_link_uid", None),
        ("wan_link", None),
        ("site_block", "dc-edge"),
    ),
)


def _model(terminal, complete, exits):
    target = EDGE if terminal == "unknown" else DELIVERY
    return ModelInput(
        "a" * 64,
        (
            NodeSpec(ROUTING, (EdgeSpec("fib:vrf:r1:0.0.0.0/0:0", target),)),
            NodeSpec(target, terminal=terminal, complete=complete, left_estate=exits),
        ),
        (EntrySpec(ROUTING),),
        (ChoiceAssignment("only"),),
        True,
    )


def _walk(model):
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        compiled = compile_model(model, manager, manager.schema.field_names)
        packets = header(
            manager,
            {"source_address": 1, "destination_address": 2, "protocol": 6},
            explicitly_all=manager.schema.field_names,
        )
        result = walk(compiled, packets, request_id="edge")
        choice = result.by_choice[0]
        return {
            "bounds": (result.bounds.lower.is_empty(), result.bounds.upper.is_empty()),
            "gaps": result.gap_refs,
            "terminals": [(t.state, t.outcome, t.left_estate) for t in choice.terminal_reaches],
            "scoped": [(g.code, g.state, g.left_estate) for g in choice.scoped_gaps],
            "top": [(g.code, g.state, g.left_estate) for g in result.scoped_gaps],
        }


@pytest.mark.parametrize(("terminal", "complete"), [("unknown", False), ("permit", True)])
def test_each_record_of_the_terminal_carries_the_object_and_the_answer_is_unchanged(terminal, complete):
    marked, plain = _walk(_model(terminal, complete, EXIT)), _walk(_model(terminal, complete, ()))

    assert marked["bounds"] == plain["bounds"]
    assert marked["gaps"] == plain["gaps"]
    assert marked["terminals"] and all(item[2] == EXIT for item in marked["terminals"])
    assert [item[:2] for item in marked["terminals"]] == [item[:2] for item in plain["terminals"]]
    assert all(item[2] == () for item in plain["terminals"])
    assert [item[:2] for item in marked["scoped"]] == [item[:2] for item in plain["scoped"]]
    assert all(item[2] == (EXIT if item[1] == marked["terminals"][0][0] else ()) for item in marked["scoped"])
    # the walk's own copies of the undecided gaps keep the object
    assert [item[:2] for item in marked["top"]] == [item[:2] for item in plain["top"]]
    assert all(item[2] == (EXIT if item[1] == marked["terminals"][0][0] else ()) for item in marked["top"])
    if terminal == "unknown":
        assert {code for code, _state, _exits in marked["scoped"]} >= {
            "MODEL_SCOPE_INCOMPLETE",
            "MODEL_OUTCOME_UNKNOWN",
        }


def test_a_routing_state_carries_none():
    model = _model("unknown", False, EXIT)
    marked = _walk(model)
    assert not any(item[1] == ROUTING and item[2] for item in marked["scoped"])


def test_the_builder_passes_at_a_recognized_next_hop_edge_and_not_for_an_estate_destination():
    from tests.test_symbolic_left_estate import _exit, _Gates, _one_default

    from hst.impact.evaluate import Interface

    far = (Interface("r2", "if:r2:far", "far", "c2", ("172.16.0.0/24",), ("172.16.0.1",)),)
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        outcomes = {}
        for destination in ("198.51.100.7", "172.16.0.9"):
            _n, _g, _r, model = _one_default(
                _Gates({"192.0.2.254": _exit(None)}), extra=far, destination=destination
            )
            compiled = compile_model(model, manager, manager.schema.field_names)
            packets = header(
                manager,
                {
                    "source_address": int(ipaddress.ip_address("10.0.0.10")),
                    "destination_address": int(ipaddress.ip_address(destination)),
                    "protocol": 6,
                },
                explicitly_all=manager.schema.field_names,
            )
            result = walk(compiled, packets, request_id="edge")
            choice = result.by_choice[0]
            outcomes[destination] = (
                not result.bounds.lower.is_empty(),
                sorted({(t.outcome, bool(t.left_estate)) for t in choice.terminal_reaches}),
            )
    assert outcomes["198.51.100.7"] == (True, [("permit", True)])
    assert outcomes["172.16.0.9"] == (False, [("unknown", False)])


def test_a_round_trip_walks_its_reply_from_the_next_hop_edge_and_names_it():
    """The reply enters on the edge's egress interface (`reply-ingress`), as
    from an interface-only delivery, and is walked back to the source; the
    result keeps the forward edge's record, so its row names the edge."""
    from dataclasses import replace

    from tests.test_symbolic_left_estate import _exit, _Gates, _one_default

    from hst.analysis_model.network_session import network_session_walk

    network, graph, request, model = _one_default(_Gates({"192.0.2.254": _exit(None)}))
    request = replace(request, success="round-trip")
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        # the request's own packets, as an assessment builds them: a field the
        # request does not state is not bound across the original and current
        # banks (`initial_relation`), so the reply's tuple swap stays small
        from hst.assessment.symbolic_evaluation import member_packets

        packets = member_packets(manager, request, request.members[0])
        compiled = compile_model(model, manager, packets.known_fields)
        result = network_session_walk(
            network,
            graph,
            request,
            request.members[0],
            manager,
            compiled,
            packets,
            estate="estate",
            request_id="edge",
        ).reply
        assert not result.bounds.lower.is_empty()
        # the forward edge's record sits on the forward walk the reply keeps
        assert result.forward is not None
        edge = [t for c in result.forward.by_choice for t in c.terminal_reaches if t.left_estate]
        assert [(t.state.location, t.outcome) for t in edge] == [
            ("estate-edge:c1:0.0.0.0/0:192.0.2.254", "permit")
        ]


def test_each_reply_is_walked_only_from_the_entry_of_its_own_forward_terminal():
    from hst.analysis_model.session_walk import session_walk
    from hst.policy.ir import Atom, Not

    lan = StateKey("delivery:vrf:r1:10.1.0.0/16", CTX, binding_scope=("reply-ingress:lan",))
    wan = StateKey("estate-edge:vrf:r1:0.0.0.0/0:192.0.2.2", CTX, binding_scope=("reply-ingress:wan",))
    inside = Atom("destination_address", "range", 0x0A010000, 0x0A01FFFF)
    forward = ModelInput(
        "a" * 64,
        (
            NodeSpec(ROUTING, (EdgeSpec("fib:lan", lan, inside), EdgeSpec("fib:wan", wan, Not(inside)))),
            NodeSpec(lan, terminal="permit"),
            NodeSpec(wan, terminal="permit", left_estate=EXIT),
        ),
        (EntrySpec(ROUTING),),
        (ChoiceAssignment("only"),),
        True,
    )
    lan_in, wan_in = StateKey("routing:reply:lan", CTX), StateKey("routing:reply:wan", CTX)
    home, drop = StateKey("delivery:reply:home", CTX), StateKey("terminal:reply:spoof", CTX)
    spoofed = Atom("source_address", "range", 0x0A010000, 0x0A01FFFF)
    reply = ModelInput(
        "a" * 64,
        (
            NodeSpec(lan_in, (EdgeSpec("lan:home", home),)),
            NodeSpec(
                wan_in, (EdgeSpec("wan:spoof", drop, spoofed), EdgeSpec("wan:home", home, Not(spoofed)))
            ),
            NodeSpec(home, terminal="permit"),
            NodeSpec(drop, terminal="deny"),
        ),
        (EntrySpec(lan_in), EntrySpec(wan_in)),
        (ChoiceAssignment("only"),),
        True,
    )
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        # a request states its fields; an unstated one is not bound across the
        # banks (`initial_relation`), so the reply's tuple swap stays small
        packets = header(
            manager,
            {
                "source_address": 0x0A000005,
                "destination_address": 0x0A010005,
                "protocol": 6,
                "destination_port": 443,
            },
        )
        names = packets.known_fields
        forward_model = compile_model(forward, manager, names)
        reply_model = compile_model(reply, manager, names)
        bound = session_walk(
            forward_model, reply_model, packets, request_id="rt", entry_terminals=(lan, wan)
        ).reply
        shared = session_walk(forward_model, reply_model, packets, request_id="rt").reply
        assert not bound.bounds.lower.is_empty()
        assert shared.bounds.lower.is_empty()


@pytest.mark.parametrize("translated", [True, False], ids=["source-nat", "no-source-nat"])
def test_an_equal_cost_choice_walks_its_reply_by_the_uplink_it_can_return_by(translated):
    from hst.analysis_model.session_walk import session_walk

    one = StateKey("estate-edge:vrf:r1:0.0.0.0/0:192.0.2.1", CTX, binding_scope=("reply-ingress:a",))
    two = StateKey("estate-edge:vrf:r1:0.0.0.0/0:192.0.2.2", CTX, binding_scope=("reply-ingress:b",))
    address = {"a": 0xC000020A, "b": 0xC0000214}
    rewrite = {name: ((("source_address", value),) if translated else ()) for name, value in address.items()}
    choices = (ChoiceAssignment("a", (("ecmp", "a"),)), ChoiceAssignment("b", (("ecmp", "b"),)))
    forward = ModelInput(
        "a" * 64,
        (
            NodeSpec(
                ROUTING,
                (
                    EdgeSpec("fib:a", one, rewrites=rewrite["a"], choices=(("ecmp", "a"),)),
                    EdgeSpec("fib:b", two, rewrites=rewrite["b"], choices=(("ecmp", "b"),)),
                ),
            ),
            NodeSpec(one, terminal="permit", left_estate=EXIT),
            NodeSpec(two, terminal="permit", left_estate=EXIT),
        ),
        (EntrySpec(ROUTING),),
        choices,
        True,
    )
    in_a, in_b = StateKey("routing:reply:a", CTX), StateKey("routing:reply:b", CTX)
    home, drop = StateKey("delivery:reply:home", CTX), StateKey("terminal:reply:spoof", CTX)
    reply = ModelInput(
        "a" * 64,
        (
            NodeSpec(in_a, (EdgeSpec("a:home", home),)),
            NodeSpec(in_b, (EdgeSpec("b:spoof", drop),)),
            NodeSpec(home, terminal="permit"),
            NodeSpec(drop, terminal="deny"),
        ),
        (EntrySpec(in_a), EntrySpec(in_b)),
        choices,
        True,
    )
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        packets = header(
            manager,
            {
                "source_address": 0x0A000005,
                "destination_address": 0xC6336407,
                "protocol": 6,
                "destination_port": 443,
            },
        )
        names = packets.known_fields
        forward_model = compile_model(forward, manager, names)
        reply_model = compile_model(reply, manager, names)
        bound = session_walk(
            forward_model,
            reply_model,
            packets,
            request_id="rt",
            entry_terminals=(one, two),
            edge_sources={name: ((4, value, value),) for name, value in address.items()},
        ).reply
        shared = session_walk(forward_model, reply_model, packets, request_id="rt").reply
        by_choice = {item.assignment.uid: item for item in bound.by_choice}
        a = by_choice["a"]
        if translated:
            assert not a.bounds.lower.is_empty()
            assert not any(gap.code == "REPLY_RETURN_UPLINK_UNDECIDED" for gap in a.scoped_gaps)
        else:
            assert a.bounds.lower.is_empty() and not a.bounds.upper.is_empty()
            gaps = [gap for gap in a.scoped_gaps if gap.code == "REPLY_RETURN_UPLINK_UNDECIDED"]
            assert [gap.state for gap in gaps] == [two]
        assert by_choice["b"].bounds.lower.is_empty()
        assert all(item.bounds.lower.is_empty() for item in shared.by_choice)


@pytest.mark.parametrize(
    ("own", "other", "expected"),
    [
        (True, True, "passes"),
        (False, False, "fails"),
        (True, False, "not decided"),
        (False, True, "not decided"),
    ],
    ids=["both-pass", "both-blocked", "own-passes-other-blocked", "own-blocked-other-passes"],
)
def test_a_reply_without_source_nat_is_decided_only_when_every_uplink_agrees(own, other, expected):
    """Two equal-cost uplinks, no source NAT: the outside decides by which
    uplink the reply returns. Choice a passes only when the reply passes from
    a and from b, fails only when it is blocked from both, and is otherwise
    not decided with REPLY_RETURN_UPLINK_UNDECIDED at b's terminal."""
    from hst.analysis_model.session_walk import session_walk

    one = StateKey("estate-edge:vrf:r1:0.0.0.0/0:192.0.2.1", CTX, binding_scope=("reply-ingress:a",))
    two = StateKey("estate-edge:vrf:r1:0.0.0.0/0:192.0.2.2", CTX, binding_scope=("reply-ingress:b",))
    choices = (ChoiceAssignment("a", (("ecmp", "a"),)), ChoiceAssignment("b", (("ecmp", "b"),)))
    forward = ModelInput(
        "a" * 64,
        (
            NodeSpec(
                ROUTING,
                (
                    EdgeSpec("fib:a", one, choices=(("ecmp", "a"),)),
                    EdgeSpec("fib:b", two, choices=(("ecmp", "b"),)),
                ),
            ),
            NodeSpec(one, terminal="permit", left_estate=EXIT),
            NodeSpec(two, terminal="permit", left_estate=EXIT),
        ),
        (EntrySpec(ROUTING),),
        choices,
        True,
    )
    in_a, in_b = StateKey("routing:reply:a", CTX), StateKey("routing:reply:b", CTX)
    home, drop = StateKey("delivery:reply:home", CTX), StateKey("terminal:reply:drop", CTX)
    reply = ModelInput(
        "a" * 64,
        (
            NodeSpec(in_a, (EdgeSpec("a:reply", home if own else drop),)),
            NodeSpec(in_b, (EdgeSpec("b:reply", home if other else drop),)),
            NodeSpec(home, terminal="permit"),
            NodeSpec(drop, terminal="deny"),
        ),
        (EntrySpec(in_a), EntrySpec(in_b)),
        choices,
        True,
    )
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        packets = header(
            manager,
            {
                "source_address": 0x0A000005,
                "destination_address": 0xC6336407,
                "protocol": 6,
                "destination_port": 443,
            },
        )
        names = packets.known_fields
        result = session_walk(
            compile_model(forward, manager, names),
            compile_model(reply, manager, names),
            packets,
            request_id="rt",
            entry_terminals=(one, two),
            edge_sources={},
        ).reply
        a = next(item for item in result.by_choice if item.assignment.uid == "a")
        read = (
            "passes"
            if not a.bounds.lower.is_empty()
            else "fails"
            if a.bounds.upper.is_empty()
            else "not decided"
        )
        assert read == expected
        gaps = [gap.state for gap in a.scoped_gaps if gap.code == "REPLY_RETURN_UPLINK_UNDECIDED"]
        assert gaps == ([two] if expected == "not decided" else [])
