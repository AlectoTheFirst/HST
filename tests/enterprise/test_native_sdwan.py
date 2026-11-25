"""Collected SD-WAN boundaries participate in actual network compilation."""

import importlib
import os
from types import MappingProxyType

import pytest

from hst.analysis_model.compile import compile_model
from hst.analysis_model.graph import GraphNode, GraphRelation
from hst.analysis_model.model import ChoiceAssignment, EntrySpec, ModelInput, NodeSpec, StateKey
from hst.analysis_model.network import normalize_network
from hst.analysis_model.overlay import _rebuild
from hst.analysis_model.sdwan_gate import project_sdwan
from hst.impact.evaluate import Member, RequestSet, member
from hst.impact.symbolic_walk import walk
from hst.policy.ir import Constant, ExecutionContext, Layer, Policy
from hst.symbolic import HeaderSchema, SymbolicManager
from hst.symbolic.predicates import header

from .test_network_compile import _graph, _ivals, _network

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")


@pytest.mark.parametrize("known_policy_denial", [False, True])
def test_boundary_retains_ingress_denial_but_not_an_assumed_exhaustive_rib(known_policy_denial):
    graph = _graph()
    boundary = GraphNode("boundary", frozenset({"ForwardingBoundary"}), MappingProxyType({}))
    device = GraphNode("device", frozenset({"Device"}), MappingProxyType({}))
    graph = _rebuild(
        graph,
        {boundary.uid: boundary, device.uid: device},
        [GraphRelation("binding", "HAS_BOUNDARY", device.uid, boundary.uid, MappingProxyType({}))],
    )
    context = ExecutionContext("estate", "graph", "graph", "device", "vrf", 4)
    key = StateKey("routing:vrf", context)
    policy = (
        Policy(
            "policy",
            "revision",
            context,
            (Layer("layer", (), "deny"),),
            ("layer",),
            installation=Constant(True),
            manifest_digest="a" * 64,
        )
        if known_policy_denial
        else None
    )
    source = ModelInput(
        "a" * 64,
        (NodeSpec(key, terminal="no_route", policy=policy),),
        (EntrySpec(key),),
        (ChoiceAssignment("only"),),
        True,
    )
    source = project_sdwan(source, graph, {"vrf": "device"})
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        packets = header(manager, {}, explicitly_all=manager.schema.field_names)
        result = walk(compile_model(source, manager, packets.known_fields), packets, request_id="boundary")
        assert result.bounds.lower.is_empty()
        assert result.bounds.upper.is_empty() is known_policy_denial


def test_observed_rib_does_not_bypass_opaque_collected_boundary():
    graph = _graph()
    boundary = GraphNode("vco:boundary", frozenset({"ForwardingBoundary"}), MappingProxyType({}))
    device = GraphNode("r1", frozenset({"Device"}), MappingProxyType({"platform": "velocloud-edge"}))
    graph = _rebuild(
        graph,
        {boundary.uid: boundary, device.uid: device},
        [GraphRelation("boundary-binding", "HAS_BOUNDARY", device.uid, boundary.uid, MappingProxyType({}))],
    )
    request = RequestSet(
        "sdwan",
        _ivals("10.0.0.10"),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
        source_context="c1",
    )
    source = normalize_network(_network(), graph, request, request.members[0], "estate")
    assert any(
        getattr(edge.predicate, "code", None) == "SDWAN_DYNAMIC_STEERING_OPAQUE"
        for node in source.nodes
        for edge in node.edges
    )
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        packets = header(
            manager,
            {
                "source_address": request.sources[0][1],
                "destination_address": request.members[0].addresses[0][1],
            },
            explicitly_all=manager.schema.field_names,
        )
        result = walk(compile_model(source, manager, packets.known_fields), packets, request_id="sdwan")
        assert result.bounds.lower.is_empty()
        assert not result.bounds.upper.is_empty()
