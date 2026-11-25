"""Missing firewall policy evidence cannot become an unfiltered routing proof."""

import importlib
import os
from types import MappingProxyType

import pytest

from hst.analysis_model.compile import compile_model
from hst.analysis_model.graph import GraphNode
from hst.analysis_model.network import normalize_network
from hst.analysis_model.overlay import _rebuild
from hst.impact.evaluate import Member, RequestSet, member
from hst.impact.symbolic_walk import walk
from hst.symbolic import HeaderSchema, SymbolicManager
from hst.symbolic.predicates import header

from .test_network_compile import _contexts_graph, _graph, _ivals, _network

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")


@pytest.mark.parametrize("role", ["firewall", "router"])
def test_known_firewall_without_installation_stays_unknown(role):
    device = GraphNode("r1", frozenset({"Device"}), MappingProxyType({"role": role}))
    # c1 and c2 are recorded global tables, as a collector writes them: an
    # unrecorded context is followed as undecided
    graph = _rebuild(_graph(), {**_contexts_graph(c1=True, c2=True).nodes, device.uid: device}, [])
    request = RequestSet(
        "missing-policy",
        _ivals("10.0.0.10"),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
        source_context="c1",
    )
    source = normalize_network(_network(), graph, request, request.members[0], "estate")
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        packets = header(
            manager,
            {
                "source_address": request.sources[0][1],
                "destination_address": request.members[0].addresses[0][1],
            },
            explicitly_all=manager.schema.field_names,
        )
        result = walk(compile_model(source, manager, packets.known_fields), packets, request_id="policy")
        assert result.bounds.lower.is_empty() is (role == "firewall")
        assert not result.bounds.upper.is_empty()
