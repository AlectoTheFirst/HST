"""MTU projection preserves packet bounds and independent routing failures."""

import importlib
import os
from dataclasses import replace

import pytest

from hst.analysis_model.compile import compile_model
from hst.analysis_model.model import ChoiceAssignment, EdgeSpec, EntrySpec, ModelInput, NodeSpec, StateKey
from hst.analysis_model.mtu_gate import project_mtu
from hst.analysis_model.network import normalize_network, normalize_reply_network
from hst.core.mtu_profiles import observation_from_raw
from hst.impact.evaluate import Interface, Member, MtuRequirement, RequestSet, member
from hst.impact.symbolic_walk import walk
from hst.policy.ir import ExecutionContext
from hst.symbolic import HeaderSchema, SymbolicManager
from hst.symbolic.predicates import header

from .test_network_compile import _graph, _ivals, _network

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")

CTX = ExecutionContext("estate", "authority", "domain", "instance", "vrf", 4)
GATE = StateKey("egress", CTX, "mtu")
DOWN = StateKey("delivery", CTX)


def _iface(limit=1400):
    observation = observation_from_raw(
        subject_uid="if:one",
        source="test",
        source_target="synthetic",
        source_field="mtu",
        raw_value=limit,
        profile_id="ip_packet",
        metric="ipv4_mtu_bytes",
        direction="tx",
        bound_kind="ceiling",
        enforcement="l3",
        assertion_kind="configured",
    )
    return Interface(
        "device",
        "if:one",
        "eth0",
        "vrf",
        (),
        (),
        mtu_observations_json=(observation.model_dump_json(),),
    )


def _model(terminal="permit", shape=None):
    nodes = [NodeSpec(GATE, (EdgeSpec("continue", DOWN),)), NodeSpec(DOWN, terminal=terminal)]
    entry = GATE
    if shape:
        entry = StateKey("shape", CTX, shape)
        nodes.append(NodeSpec(entry, (EdgeSpec("reoriginate", GATE),)))
    return ModelInput("a" * 64, tuple(nodes), (EntrySpec(entry),), (ChoiceAssignment("only"),), True)


def _bounds(model):
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        compiled = compile_model(model, manager, manager.schema.field_names)
        packets = header(
            manager,
            {"source_address": 1, "destination_address": 2, "protocol": 17},
            explicitly_all=manager.schema.field_names,
        )
        result = walk(compiled, packets, request_id="mtu")
        return result.bounds.lower.is_empty(), result.bounds.upper.is_empty()


@pytest.mark.parametrize("mode", [None, "off", "inventory"])
def test_non_size_modes_preserve_model(mode):
    model = _model()
    requirement = MtuRequirement(mode) if mode is not None else None
    assert project_mtu(model, requirement, {GATE: _iface()}) is model


def test_known_unfragmented_deficit_is_a_definite_denial():
    model = project_mtu(_model(), MtuRequirement("unfragmented", 1500), {GATE: _iface()})
    assert _bounds(model) == (True, True)


@pytest.mark.parametrize("terminal", ["deny", "no_route"])
def test_missing_mtu_does_not_hide_downstream_failure(terminal):
    interface = replace(_iface(), mtu_observations_json=())
    model = project_mtu(_model(terminal), MtuRequirement("packet", 1200), {GATE: interface})
    assert _bounds(model) == (True, True)


def test_local_capacity_does_not_prove_complete_path_mtu():
    model = project_mtu(_model(), MtuRequirement("unfragmented", 1200), {GATE: _iface()})
    assert _bounds(model) == (True, False)
    assert any(
        getattr(edge.predicate, "code", None) == "MTU_PATH_COVERAGE_INCOMPLETE"
        for node in model.nodes
        for edge in node.edges
    )


@pytest.mark.parametrize("shape", ["proxy", "load-balancer", "tunnel"])
def test_changed_packet_shape_does_not_reuse_original_length(shape):
    model = project_mtu(_model(shape=shape), MtuRequirement("unfragmented", 1500), {GATE: _iface()})
    assert _bounds(model) == (True, False)


def test_reply_uses_explicit_reply_size_and_does_not_inherit_df():
    request = MtuRequirement("unfragmented", 1200, reply_ip_packet_bytes=1500)
    assert _bounds(project_mtu(_model(), request, {GATE: _iface()}, reply=True)) == (True, True)
    request = MtuRequirement("packet", 1200, ipv4_df=True, reply_ip_packet_bytes=1500)
    assert _bounds(project_mtu(_model(), request, {GATE: _iface()}, reply=True)) == (True, False)


def test_egress_before_tunnel_chain_does_not_assume_carrier_packet_size():
    tunnel = StateKey("tunnel", CTX, "tunnel")
    model = _model()
    model = replace(
        model,
        nodes=(
            NodeSpec(GATE, (EdgeSpec("continue", tunnel),)),
            NodeSpec(tunnel, (EdgeSpec("encapsulate", DOWN),)),
            NodeSpec(DOWN, terminal="permit"),
        ),
    )
    model = project_mtu(model, MtuRequirement("unfragmented", 1500), {GATE: _iface()})
    assert _bounds(model) == (True, False)


def test_network_adapter_wires_forward_and_reply_mtu():
    network = _network()
    # the reply's way back to the source: the reply model reads only the routes
    # a reply toward the sources takes, so r2 needs its route to the LAN
    network = replace(
        network,
        routing=replace(
            network.routing,
            connected=[
                *network.routing.connected,
                {"context_uid": "c2", "prefix": "192.0.2.0/24", "interface": "lan"},
            ],
            static=[
                *network.routing.static,
                {"context_uid": "c2", "prefix": "10.0.0.0/24", "next_hop": "192.0.2.1"},
            ],
        ),
    )
    network = replace(
        network,
        interfaces=tuple(
            replace(interface, mtu_observations_json=_iface().mtu_observations_json)
            for interface in network.interfaces
        ),
    )
    request = RequestSet(
        "mtu",
        _ivals("10.0.0.10"),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
        source_context="c1",
        mtu=MtuRequirement("unfragmented", 1200, reply_ip_packet_bytes=1500),
    )
    forward = normalize_network(network, _graph(), request, request.members[0], "estate")
    assert not any(node.key.stage == "mtu" and node.terminal == "deny" for node in forward.nodes)
    terminals = tuple(node.key for node in forward.nodes if node.terminal == "permit")
    reply = normalize_reply_network(network, _graph(), request, request.members[0], "estate", terminals)
    assert any(node.key.stage == "mtu" and node.terminal == "deny" for node in reply.nodes)
