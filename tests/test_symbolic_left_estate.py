"""Where a symbolic-v2 path leaves the estate (`left_estate`)."""

# ruff: noqa: F811 -- the imported `graph` fixture is shadowed by design in every test signature

from __future__ import annotations

import copy
import importlib
import ipaddress
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from tests import test_impact_left_estate as le
from tests.enterprise import test_network_compile as nc
from tests.support.demo_trace_graph import TraceGraph
from tests.test_demo_enterprise_internet_edge_trace import _blocks, _raw
from tests.test_impact_evaluate import graph  # noqa: F401

from hst.analysis_model import network as netmod
from hst.analysis_model.compile import AnalysisModel, CompiledNode, with_estate_exits
from hst.analysis_model.model import (
    ChoiceAssignment,
    EntrySpec,
    ModelInput,
    NodeSpec,
    StateKey,
    semantic_fingerprint,
)
from hst.analysis_model.mtu_gate import project_mtu
from hst.analysis_model.network import normalize_network, normalize_request_network
from hst.app.agent import traffic
from hst.assessment import symbolic_results
from hst.impact.evaluate import Interface, Member, MtuRequirement, Network, RequestSet, Service, member
from hst.impact.symbolic_walk import TerminalReach, WalkGap
from hst.path.addrsets import _ports
from hst.policy.ir import ExecutionContext
from hst.simul.rib import RibInput

ev = importlib.import_module("hst.impact.evaluate")
CTX = le.estate.VRF_R1
EDGE = f"terminal:unknown-hop:{CTX}:0.0.0.0/0"
DELIVERY = f"delivery:{CTX}:0.0.0.0/0"
NEXT_HOP_EDGE = f"estate-edge:{CTX}:0.0.0.0/0:192.0.2.2"
ESTATE_DELIVERY = f"estate-delivery:{CTX}:0.0.0.0/0"
SPLIT = f"estate-edge-split:{CTX}:0.0.0.0/0:192.0.2.2"


def _models(static, request=None):
    """The routing models of the impact estate with `static`, for a flow to an internet address."""
    request = request or le.estate._request(dst=le.INTERNET)
    return normalize_request_network(le._network(static), nc._graph(), request, "estate")


def _terminals(models):
    """Each terminal of every member: location -> (terminal, complete, binding scope, objects)."""
    return {
        node.key.location: (
            node.terminal,
            node.complete,
            node.key.binding_scope,
            [dict(item) for item in node.left_estate],
        )
        for model in models.values()
        for node in model.nodes
        if node.terminal is not None
    }


def _bare(models):
    """The fingerprint of each member's model with every object removed."""
    return {
        name: semantic_fingerprint(
            replace(model, nodes=tuple(replace(node, left_estate=()) for node in model.nodes))
        )
        for name, model in models.items()
    }


# --- the routing node builder -------------------------------------------------------------


@pytest.mark.parametrize(
    ("static", "uplink", "wan", "location", "expected"),
    [
        pytest.param(
            le.NEXT_HOP,
            le._row(link="wan:1", kind="dia"),
            None,
            NEXT_HOP_EDGE,
            le._exit("wan-link", link="DIA"),
            id="wan-link",
        ),
        pytest.param(
            le.NEXT_HOP,
            le._row(origin=True),
            None,
            NEXT_HOP_EDGE,
            le._exit("access-client-default"),
            id="access-default",
        ),
        pytest.param(
            le.NEXT_HOP,
            le._row(zone="internet"),
            None,
            NEXT_HOP_EDGE,
            le._exit("site-zone", block="dc-edge"),
            id="zone-next-hop",
        ),
        pytest.param(
            le.IFACE_ONLY,
            None,
            {"uid": "wan:1", "name": "DIA", "kind": "dia"},
            ESTATE_DELIVERY,
            le._exit("wan-link", next_hop=None, link="DIA"),
            id="iface-only-wan-link",
        ),
        pytest.param(
            le.IFACE_ONLY,
            le._row(zone="internet"),
            None,
            ESTATE_DELIVERY,
            le._exit("site-zone", next_hop=None, block="dc-edge"),
            id="zone-iface",
        ),
    ],
)
def test_a_recognized_edge_passes_with_the_object_on_its_terminal(
    graph, static, uplink, wan, location, expected
):
    le._answers(graph)
    graph.wan = None
    plain = _models(static)
    le._answers(graph, uplink)
    graph.wan = wan
    marked = _models(static)

    found, before = _terminals(marked), _terminals(plain)
    assert found[location][3] == [expected]
    assert found[location][:3] == ("permit", True, ("reply-ingress:if:r1-eth3",))
    assert not any(v[3] for k, v in found.items() if k != location)
    assert not any(v[3] for v in before.values())
    # a model that carries one has its own fingerprint (a cache never serves another's)
    assert all(semantic_fingerprint(marked[name]) != semantic_fingerprint(plain[name]) for name in plain)
    if location == ESTATE_DELIVERY:
        estate_destination = f"terminal:estate-destination:{CTX}:0.0.0.0/0"
        assert before[DELIVERY] == ("permit", True, ("reply-ingress:if:r1-eth3",), [])
        assert DELIVERY not in found
        assert found[estate_destination] == ("unknown", False, (), [])
        split = next(
            n
            for m in marked.values()
            for n in m.nodes
            if n.key.location == f"estate-delivery-split:{CTX}:0.0.0.0/0"
        )
        assert [(e.uid, e.target.location) for e in split.edges] == [
            ("estate:held", estate_destination),
            ("estate:outside", ESTATE_DELIVERY),
        ]
    else:
        assert before[EDGE][:2] == ("unknown", False) and location not in before
        assert found[EDGE][:2] == ("unknown", False)
        split = next(n for m in marked.values() for n in m.nodes if n.key.location == SPLIT)
        assert [(e.uid, e.target.location) for e in split.edges] == [
            ("estate:held", EDGE),
            ("estate:outside", NEXT_HOP_EDGE),
        ]
        held = split.edges[0].predicate
        assert sorted((a.value, a.other) for a in held.terms) == sorted(
            (low, high) for af, low, high in le._network(static).estate_prefixes if af == 4
        )


@pytest.mark.parametrize(
    ("static", "uplink", "boundary"),
    [
        pytest.param(le.NEXT_HOP, None, None, id="no-mark"),
        pytest.param(le.NEXT_HOP, le._row(zone="external"), None, id="zone-external"),
        pytest.param(le.NEXT_HOP, le._row(zone="internal"), None, id="zone-internal"),
        pytest.param(
            le.NEXT_HOP, le._row(zone="internet", link="wan:m", kind="mpls"), None, id="mpls-outranks-zone"
        ),
        pytest.param(le.NEXT_HOP, le._row(link="wan:m", kind="mpls"), None, id="mpls"),
        pytest.param(le.IFACE_ONLY, le._row(zone="external"), None, id="iface-zone-external"),
        pytest.param(le.IFACE_ONLY, le._row(origin=True), None, id="iface-access-origin"),
        pytest.param(
            le.NEXT_HOP, le._row(link="wan:1", kind="dia"), {"boundary_uid": "fb:1"}, id="sdwan-edge"
        ),
    ],
)
def test_any_other_end_keeps_the_terminals_and_fingerprints(graph, static, uplink, boundary):
    le._answers(graph)
    graph.wan = None
    plain = _models(static)
    le._answers(graph, uplink, boundary)
    marked = _models(static)

    assert _terminals(marked) == _terminals(plain)
    assert {n: semantic_fingerprint(m) for n, m in marked.items()} == {
        n: semantic_fingerprint(m) for n, m in plain.items()
    }


def test_a_next_hop_the_graph_holds_is_no_edge_even_when_the_model_lacks_it(graph):
    """The tracer's own owner read decides: a collected device the model left
    out is not outside the estate."""
    le._answers(graph, le._row(link="wan:1", kind="dia"))
    graph.next_hop_devs["192.0.2.2"] = {
        "dev_uid": "dev:isp-ce",
        "dev_name": "ce",
        "if_uid": "if:ce-0",
        "if_name": "ge0",
        "l3dom": None,
        "anchor": CTX,
    }
    assert _terminals(_models(le.NEXT_HOP))[EDGE] == ("unknown", False, (), [])


def test_an_interface_only_route_inside_the_estate_gets_none_and_is_not_asked(graph):
    """An interface-only route that is not the default of its family is the
    normal form of a delivery inside the estate."""
    le._answers(graph, le._row(zone="internet"))
    asked, answer = [], graph.read_one

    def spy(query, **params):
        asked.append(query)
        return answer(query, **params)

    graph.read_one = spy
    static = {**le.estate._static("198.51.100.0/24", None), "interface": "eth3"}
    models = _models(static)

    location = f"delivery:{CTX}:198.51.100.0/24"
    assert _terminals(models)[location] == ("permit", True, ("reply-ingress:if:r1-eth3",), [])
    assert le.tracemod._EGRESS_UPLINK_QUERY not in asked


def test_a_pure_model_has_no_reader_and_keeps_its_fingerprints():
    pinned = {
        "203.0.113.10": "f5fdd7f6347f76d6f801e8783b6bfb3f1a8af815b02b2a90f326ad605d529c77",
        "198.51.100.7": "bd8d5d91ac25c65ad79eda7a207325510a9f74e1db1cda019a8ee56f1e3e02e5",
    }
    network = nc._network()
    network.routing.static.append({"context_uid": "c1", "prefix": "0.0.0.0/0", "next_hop": "192.0.2.254"})
    for destination, fingerprint in pinned.items():
        request = RequestSet(
            "x",
            nc._ivals("10.0.0.10"),
            "s",
            (Member("s", nc._ivals(destination)),),
            member("s"),
            source_context="c1",
        )
        model = normalize_network(
            network, nc._contexts_graph(c1=True, c2=True), request, request.members[0], "estate"
        )
        assert semantic_fingerprint(model) == fingerprint
        assert not any(node.left_estate for node in model.nodes)
    network = nc._network()
    network.routing.static.append({"context_uid": "c1", "prefix": "0.0.0.0/0", "interface": "wan"})
    request = RequestSet(
        "x",
        nc._ivals("10.0.0.10"),
        "s",
        (Member("s", nc._ivals("198.51.100.7")),),
        member("s"),
        source_context="c1",
    )
    model = normalize_network(
        network, nc._contexts_graph(c1=True, c2=True), request, request.members[0], "estate"
    )
    assert semantic_fingerprint(model) == "250f2acbe6657fd1af26316c58f4a475acdaf2592fa8c1b427ea58f85f633591"


# --- the rows on one terminal, and one read per route ----------------------------------------


class _Gates:
    """Gates that answer `estate_exit` per next hop and count the reads."""

    def __init__(self, exits):
        self.exits, self.calls = exits, []

    def with_changes(self, _changes):
        return self

    def estate_exit(self, device_uid, context_uid, route, out_if):
        self.calls.append((device_uid, context_uid, route["cidr"], route["next_hop"], out_if.uid))
        found = self.exits.get(route["next_hop"])
        return None if found is None else {**found, "next_hop": route["next_hop"]}


def _exit(next_hop):
    return {
        "basis": "wan-link",
        "device_uid": "r1",
        "device": "r1",
        "interface_uid": "if:r1:wan",
        "interface": "wan",
        "next_hop": next_hop,
        "wan_link_uid": "wan:1",
        "wan_link": "DIA",
        "site_block": None,
    }


def _ecmp(gates):
    network = nc._network()
    network = replace(network, gates=gates)
    network.routing.static.extend(
        [
            {"context_uid": "c1", "prefix": "0.0.0.0/0", "next_hop": "192.0.2.253"},
            {"context_uid": "c1", "prefix": "0.0.0.0/0", "next_hop": "192.0.2.254"},
        ]
    )
    request = RequestSet(
        "x",
        nc._ivals("10.0.0.10"),
        "s",
        (Member("one", nc._ivals("198.51.100.7")), Member("two", nc._ivals("198.51.100.8"))),
        member("one"),
        source_context="c1",
    )
    return normalize_request_network(network, nc._contexts_graph(c1=True, c2=True), request, "estate")


def test_equal_cost_edges_list_each_object_in_the_tracers_order_and_read_each_route_once():
    gates = _Gates({"192.0.2.254": _exit(None), "192.0.2.253": _exit(None)})
    models = _ecmp(gates)

    for model in models.values():
        edges = {n.key.location: n for n in model.nodes if n.key.location.startswith("estate-edge:")}
        assert sorted(edges) == [
            "estate-edge:c1:0.0.0.0/0:192.0.2.253",
            "estate-edge:c1:0.0.0.0/0:192.0.2.254",
        ]
        for location, node in edges.items():
            # each equal-cost path passes at its own edge and names only its own next hop
            assert [dict(item)["next_hop"] for item in node.left_estate] == [location.rsplit(":", 1)[1]]
            assert (node.terminal, node.complete) == ("permit", True)
    # two members, two rows: each route is read once for this gates object
    assert sorted(call[3] for call in gates.calls) == ["192.0.2.253", "192.0.2.254"]
    assert {call[4] for call in gates.calls} == {"if:r1:wan"}


def test_an_equal_cost_path_that_is_no_edge_stays_undecided():
    models = _ecmp(_Gates({"192.0.2.254": _exit(None)}))
    for model in models.values():
        node = next(n for n in model.nodes if n.key.location == "terminal:unknown-hop:c1:0.0.0.0/0")
        assert (node.terminal, node.complete, node.left_estate) == ("unknown", False, ())
        routing = next(n for n in model.nodes if n.key.location == "routing:c1:ingress:none")
        targets = sorted(
            edge.target.location for edge in routing.edges if ":0.0.0.0/0" in edge.target.location
        )
        assert targets == [
            "estate-edge-split:c1:0.0.0.0/0:192.0.2.254",
            "terminal:unknown-hop:c1:0.0.0.0/0",
        ]


def test_the_merge_of_rows():
    one, two = tuple(_exit("192.0.2.1").items()), tuple(_exit("192.0.2.2").items())
    assert netmod._edge_exits([two, one, two]) == (one, two)
    assert netmod._edge_exits([one, None]) == ()
    assert netmod._edge_exits([]) == ()


# --- the projections that move or end a terminal --------------------------------------------


_CTX = ExecutionContext("estate", "authority", "domain", "instance", "vrf", 4)
_OBJECT = (tuple(_exit("192.0.2.1").items()),)


def test_only_a_terminal_carries_an_object():
    with pytest.raises(ValueError, match="only a terminal"):
        NodeSpec(StateKey("routing", _CTX), left_estate=_OBJECT)


def test_the_mtu_projection_moves_the_object_with_the_delivery():
    delivery = StateKey("delivery", _CTX)
    model = ModelInput(
        "a" * 64,
        (NodeSpec(delivery, terminal="permit", left_estate=_OBJECT),),
        (EntrySpec(delivery),),
        (ChoiceAssignment("only"),),
        True,
    )
    projected = {
        node.key.location: node for node in project_mtu(model, MtuRequirement("packet", 1500), {}).nodes
    }

    assert projected["delivery"].terminal is None and projected["delivery"].left_estate == ()
    assert projected["mtu-delivery:delivery"].terminal == "permit"
    assert projected["mtu-delivery:delivery"].left_estate == _OBJECT


def test_a_stored_compiled_model_takes_the_object_from_its_source():
    """The model cache stores no object (`codec`); its key, the source's
    fingerprint, holds it, and a loaded model takes it from the source."""
    edge, other = StateKey("edge", _CTX), StateKey("other", _CTX)
    source = ModelInput(
        "a" * 64,
        (
            NodeSpec(edge, terminal="unknown", complete=False, left_estate=_OBJECT),
            NodeSpec(other, terminal="deny"),
        ),
        (EntrySpec(edge),),
        (ChoiceAssignment("only"),),
        True,
    )
    stored = AnalysisModel(
        "a" * 64,
        "fp",
        None,
        (CompiledNode(edge, (), (), False, ()), CompiledNode(other, (), (), True, ())),
        (),
        (),
        True,
    )
    loaded = {node.key: node for node in with_estate_exits(stored, source).nodes}  # type: ignore[arg-type]

    assert loaded[edge].left_estate == _OBJECT
    assert loaded[other].left_estate == ()
    bare = replace(source, nodes=tuple(replace(n, left_estate=()) for n in source.nodes))
    assert with_estate_exits(stored, bare) is stored  # type: ignore[arg-type]


# --- the evidence row ------------------------------------------------------------------------


def _state(location):
    return StateKey(location, ExecutionContext("estate", "graph", "graph", "dev:r1", CTX, 4))


def _symbolic_answer(terminals, gaps):
    choice = SimpleNamespace(
        assignment=ChoiceAssignment("only"), terminal_reaches=tuple(terminals), scoped_gaps=tuple(gaps)
    )
    result = SimpleNamespace(
        by_choice=(choice,), manifest_digest="a" * 64, model_fingerprint="fp", request_id="req"
    )
    return SimpleNamespace(members={"app": result}, evidence=None)


def test_a_symbolic_row_at_the_edge_carries_the_objects_and_one_sentence():
    exits = (tuple(le._exit("site-zone", block="dc-edge").items()),)
    edge, inside = _state(EDGE), _state("delivery:vrf:r1:10.0.0.0/24")
    marked = _symbolic_answer(
        [TerminalReach(edge, "unknown", None, exits), TerminalReach(inside, "permit", None)],  # type: ignore[arg-type]
        [WalkGap("MODEL_SCOPE_INCOMPLETE", None, ChoiceAssignment("only"), edge, left_estate=exits)],  # type: ignore[arg-type]
    )
    plain = _symbolic_answer(
        [TerminalReach(edge, "unknown", None), TerminalReach(inside, "permit", None)],  # type: ignore[arg-type]
        [WalkGap("MODEL_SCOPE_INCOMPLETE", None, ChoiceAssignment("only"), edge)],  # type: ignore[arg-type]
    )
    rows = symbolic_results._evidence(marked, plain)["items"]  # type: ignore[arg-type]
    before = [row for row in rows if row["side"] == "before"]
    after = [row for row in rows if row["side"] == "after"]

    note = (
        "the last hop is outside the estate: r1 eth3 to next hop 192.0.2.2 "
        '(the operator\'s site zone "internet" of block dc-edge)'
    )
    at_edge = [row for row in before if row["state"]["location"] == EDGE]
    assert [row["kind"] for row in at_edge] == ["terminal", "gap"]
    for row in at_edge:
        assert row["left_estate"] == [le._exit("site-zone", block="dc-edge")]
        assert row["left_estate_note"] == note
    # every other row, and the same rows without the object, have neither key
    assert not any({"left_estate", "left_estate_note"} & set(row) for row in before if row not in at_edge)
    assert not any({"left_estate", "left_estate_note"} & set(row) for row in after)
    sided = ("side", "artifact_root")
    for marked_row, plain_row in zip(before, after, strict=True):
        stripped = {
            k: v for k, v in marked_row.items() if k not in ("left_estate", "left_estate_note", *sided)
        }
        assert stripped == {k: v for k, v in plain_row.items() if k not in sided}
    json.dumps(rows)


# --- the allowed_traffic tool -----------------------------------------------------------------


def test_the_traffic_tool_passes_the_edge_on_its_evidence(graph):
    le._answers(graph, le._row(zone="internet"))
    src = traffic.resolve(None, traffic.AddressSelector(kind="addresses", addresses=["10.0.0.0/24"]))
    dst = traffic.resolve(None, traffic.AddressSelector(kind="addresses", addresses=[le.INTERNET]))
    service = Service(frozenset({6}), tuple(_ports("443")), tuple(_ports("any")))
    marked = traffic.evaluate(le._network(le.NEXT_HOP), src, dst, service)
    le._answers(graph)
    plain = traffic.evaluate(le._network(le.NEXT_HOP), src, dst, service)

    items = marked["evidence"]["items"]
    edge = [item for item in items if "left_estate" in item]
    assert edge and all(item["outcome"] == ev.HOLDS and item["missing"] == [] for item in edge)
    assert edge[0]["left_estate"] == [le._exit("site-zone", block="dc-edge")]
    assert edge[0]["left_estate_note"].startswith("the last hop is outside the estate: r1 eth3")
    assert marked["allowed"]["items"] and not marked["not_established"]["items"]
    assert plain["not_established"]["items"] and not plain["allowed"]["items"]
    assert not any("left_estate" in item for item in plain["evidence"]["items"])


# --- the demo estate ----------------------------------------------------------------------------


class _DemoGraph(TraceGraph):
    """`TraceGraph` with the device-name read `GraphGates.estate_exit` makes:
    the hostname of a live Device, as the Cypher returns it."""

    def _answers(self):
        return {**super()._answers(), ev._DEVICE_NAME_QUERY: self._device_name}

    def _device_name(self, dev, snap):
        return [{"name": self.get(dev, "hostname")}] if self.has(dev, "Device") else []


def _demo_router(router, uplink, gateway, prefix, graph_session):
    """The routing model of one FR5 internet router of the demo estate, as its
    configuration reads (fixtures/demo-enterprise, `fr5_internet_edges`): the
    uplink GigabitEthernet0/0/1 and a static default to the provider gateway,
    which no collected interface holds."""
    context = f"vrf:{router}:default"
    default = "0.0.0.0/0" if "." in gateway else "::/0"
    return Network(
        RibInput(
            contexts=[{"uid": context, "device_uid": router, "name": "default", "platform": "iosxe"}],
            connected=[{"context_uid": context, "prefix": prefix, "interface": "GigabitEthernet0/0/1"}],
            static=[{"context_uid": context, "prefix": default, "next_hop": gateway}],
        ),
        (Interface(router, f"{router}/if/gi0-0-1", "GigabitEthernet0/0/1", context, (prefix,), (uplink,)),),
        ev.GraphGates(graph_session),
    )


_DEMO = {
    4: (
        ("10.72.101.10", "192.0.2.77"),
        ("dev:fr5-inet-01", "203.0.113.18", "203.0.113.17", "203.0.113.16/30"),
        ("dev:fr5-inet-02", "203.0.113.22", "203.0.113.21", "203.0.113.20/30"),
    ),
    6: (
        ("2001:db8:72:101::10", "2001:db8:ffff::77"),
        ("dev:fr5-inet-01", "2001:db8:72:e1::2", "2001:db8:72:e1::1", "2001:db8:72:e1::/64"),
        ("dev:fr5-inet-02", "2001:db8:72:e2::2", "2001:db8:72:e2::1", "2001:db8:72:e2::/64"),
    ),
}


def _demo_exits(version, family):
    """Each FR5 internet router's terminal objects, on the estate with the demo run's stamp
    (fr5-inet-01 zone `internet`, fr5-inet-02 zone `external`)."""
    batch = copy.deepcopy(_raw(version))
    for node in batch.nodes:
        if node.uid in _blocks():
            node.props["site_block"], node.props["site_zone"] = _blocks()[node.uid]
    session = _DemoGraph(batch)
    (source, destination), *routers = _DEMO[family]
    found = {}
    for router, uplink, gateway, prefix in routers:
        request = RequestSet(
            "internet",
            nc._ivals(source),
            "web",
            (Member("web", nc._ivals(destination)),),
            member("web"),
            source_context=f"vrf:{router}:default",
        )
        network = _demo_router(router, uplink, gateway, prefix, session)
        model = normalize_network(network, nc._graph(), request, request.members[0], "estate")
        node = min(
            (n for n in model.nodes if n.key.location.startswith(("estate-edge:", "terminal:unknown-hop:"))),
            key=lambda n: not n.key.location.startswith("estate-edge:"),
        )
        found[router] = (node.terminal, node.complete, [dict(item) for item in node.left_estate])
    assert session.refused == []
    return found


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("version", [1, 2, 3])
def test_the_demo_internet_router_is_the_edge_and_the_external_one_is_not(version, family):
    found = _demo_exits(version, family)

    assert found["dev:fr5-inet-02"] == ("unknown", False, [])
    # zone internet: the path passes at the edge and names it
    assert found["dev:fr5-inet-01"][:2] == ("permit", True)
    assert found["dev:fr5-inet-01"][2] == [
        {
            "basis": "site-zone",
            "device_uid": "dev:fr5-inet-01",
            "device": "fr5-inet-01",
            "interface_uid": "dev:fr5-inet-01/if/gi0-0-1",
            "interface": "GigabitEthernet0/0/1",
            "next_hop": _DEMO[family][1][2],
            "wan_link_uid": None,
            "wan_link": None,
            "site_block": "Internet edge",
        }
    ]


def test_the_demo_edge_names_the_router_as_the_tracer_does():
    assert [item["device"] for item in _demo_exits(1, 4)["dev:fr5-inet-01"][2]] == ["fr5-inet-01"]


# --- the neighbors of a recognized edge, and the reply from it ----------------------------------


def _one_default(gates, next_hop="192.0.2.254", extra=(), sources="10.0.0.10", destination="198.51.100.7"):
    """`nc._network` with a default route out of c1 to `next_hop`, and the
    interfaces `extra` added."""
    network = replace(nc._network(), gates=gates)
    network = replace(network, interfaces=(*network.interfaces, *extra))
    network.routing.static.append({"context_uid": "c1", "prefix": "0.0.0.0/0", "next_hop": next_hop})
    request = RequestSet(
        "x",
        nc._ivals(sources),
        "s",
        (Member("s", nc._ivals(destination)),),
        member("s"),
        source_context="c1",
    )
    graph = nc._contexts_graph(c1=True, c2=True, c3=True)
    return network, graph, request, normalize_network(network, graph, request, request.members[0], "estate")


def _locations(model, prefix):
    return sorted(n.key.location for n in model.nodes if n.key.location.startswith(prefix))


def test_an_ambiguous_next_hop_owner_stays_and_is_not_asked():
    gates = _Gates({"192.0.2.254": _exit(None)})
    extra = (
        Interface("r2", "if:r2:x", "x", "c2", ("192.0.2.0/24",), ("192.0.2.254",)),
        Interface("r3", "if:r3:x", "x", "c3", ("192.0.2.0/24",), ("192.0.2.254",)),
    )
    _network, _graph, _request, model = _one_default(gates, extra=extra)

    assert _locations(model, "terminal:next-hop-owner-ambiguous:") == [
        "terminal:next-hop-owner-ambiguous:c1:0.0.0.0/0"
    ]
    assert _locations(model, "estate-edge") == []
    assert gates.calls == []


def test_an_ipv6_flow_takes_no_ipv4_default():
    """A device with only an IPv4 default: an IPv6 flow has no route there,
    and no edge is asked or recognized."""
    gates = _Gates({"192.0.2.254": _exit(None)})
    extra = (Interface("r1", "if:r1:lan6", "lan6", "c1", ("2001:db8:1::/64",), ("2001:db8:1::1",)),)
    _network, _graph, _request, model = _one_default(
        gates, extra=extra, sources="2001:db8:1::10", destination="2001:db8:ffff::77"
    )

    assert _locations(model, "estate-edge") == []
    assert not any(node.left_estate for node in model.nodes)
    assert gates.calls == []


def test_a_destination_the_estate_holds_elsewhere_keeps_the_undecided_terminal():
    gates = _Gates({"192.0.2.254": _exit(None)})
    extra = (Interface("r2", "if:r2:far", "far", "c2", ("172.16.0.0/24",), ("172.16.0.1",)),)
    _network, _graph, _request, model = _one_default(gates, extra=extra, destination="172.16.0.9")
    nodes = {n.key.location: n for n in model.nodes}
    split = nodes["estate-edge-split:c1:0.0.0.0/0:192.0.2.254"]
    held = split.edges[0].predicate

    assert split.edges[0].target.location == "terminal:unknown-hop:c1:0.0.0.0/0"
    assert any(atom.value <= int(ipaddress.ip_address("172.16.0.9")) <= atom.other for atom in held.terms)
    assert nodes["terminal:unknown-hop:c1:0.0.0.0/0"].terminal == "unknown"
    assert nodes["estate-edge:c1:0.0.0.0/0:192.0.2.254"].terminal == "permit"


def test_the_reply_enters_at_the_edge_as_at_an_interface_only_delivery():
    from hst.analysis_model.network import normalize_reply_network

    def reply_entry(model, network, graph, request, prefix):
        edge = next(
            n.key for n in model.nodes if n.key.location.startswith(prefix) and n.terminal == "permit"
        )
        reply = normalize_reply_network(network, graph, request, request.members[0], "estate", (edge,))
        return edge.binding_scope, [entry.key.location for entry in reply.entries]

    network, graph, request, model = _one_default(_Gates({"192.0.2.254": _exit(None)}))
    at_edge = reply_entry(model, network, graph, request, "estate-edge:")

    delivery = replace(nc._network(), gates=_Gates({None: _exit(None)}))
    delivery.routing.static.append({"context_uid": "c1", "prefix": "0.0.0.0/0", "interface": "wan"})
    model = normalize_network(delivery, graph, request, request.members[0], "estate")
    at_delivery = reply_entry(model, delivery, graph, request, "estate-delivery:c1:0.0.0.0/0")

    assert at_edge == at_delivery == (("reply-ingress:if:r1:wan",), ["routing:c1:ingress:if:r1:wan"])


# --- the result vocabulary ----------------------------------------------------------------------


def test_the_left_estate_texts_use_only_result_words(graph):
    from hst.assessment import evaluation
    from hst.results.words import FORBIDDEN_WORDS, _contains_word

    texts = []
    for uplink, wan, static in (
        (le._row(link="wan:1", kind="dia"), None, le.NEXT_HOP),
        (le._row(origin=True), None, le.NEXT_HOP),
        (le._row(zone="internet"), None, le.NEXT_HOP),
        (None, {"uid": "wan:1", "name": "DIA", "kind": "dia"}, le.IFACE_ONLY),
        (le._row(zone="internet"), None, le.IFACE_ONLY),
    ):
        le._answers(graph, uplink)
        graph.wan = wan
        answer = le._answer(static)
        texts += [s.detail for m in answer.members.values() for e in m.explanations for s in e.steps[-1:]]
        texts += [
            row["left_estate_note"] for row in evaluation._evidence(answer, "before") if "left_estate" in row
        ]
    texts.append(symbolic_results._left_estate(SimpleNamespace(left_estate=_OBJECT))["left_estate_note"])
    assert len(texts) >= 11
    for text in texts:
        for word in FORBIDDEN_WORDS:
            assert not _contains_word(text.lower(), word), (word, text)


# --- the gates after routing, the memo, the forward rows ---------------------------------------


def _with_nat(graph):
    """`graph` with an interface-bound source NAT on r1 (Cisco PAT on the uplink:
    `ip nat inside source ... interface <wan> overload`)."""
    from types import MappingProxyType

    from hst.analysis_model.graph import GraphNode, GraphRelation
    from hst.analysis_model.overlay import _rebuild

    def node(uid, labels, **props):
        return GraphNode(uid, frozenset(labels), MappingProxyType({"uid": uid, **props}))

    def rel(uid, kind, start, end):
        return GraphRelation(uid, kind, start, end, MappingProxyType({}))

    nodes = dict(graph.nodes)
    nodes.update(
        {
            "r1": node("r1", ["Device"]),
            "rb:nat": node("rb:nat", ["FwRulebase"], kind="nat"),
            "nat:pat": node(
                "nat:pat", ["NatRule"], kind="snat", position=1, enabled=True, out_if="if:r1:wan"
            ),
            "pfx:lan": node("pfx:lan", ["Prefix"], cidr="10.0.0.0/24"),
            "ip:wan": node("ip:wan", ["IpAddress"], ip="192.0.2.1"),
        }
    )
    relations = [
        rel("e1", "ENFORCES", "r1", "rb:nat"),
        rel("e2", "HAS_RULE", "rb:nat", "nat:pat"),
        rel("e3", "ORIG_SRC", "nat:pat", "pfx:lan"),
        rel("e4", "XLATE_SRC", "nat:pat", "ip:wan"),
    ]
    return _rebuild(graph, nodes, relations)


def test_a_source_nat_bound_to_the_uplink_reads_its_binding_at_a_next_hop_edge():
    def model(gates):
        network = replace(nc._network(), gates=gates)
        network.routing.static.append({"context_uid": "c1", "prefix": "0.0.0.0/0", "next_hop": "192.0.2.254"})
        request = RequestSet(
            "x",
            nc._ivals("10.0.0.10"),
            "s",
            (Member("s", nc._ivals("198.51.100.7")),),
            member("s"),
            source_context="c1",
        )
        graph = _with_nat(nc._contexts_graph(c1=True, c2=True))
        return repr(normalize_network(network, graph, request, request.members[0], "estate").nodes)

    edge, plain = model(_Gates({"192.0.2.254": _exit(None)})), model(_Gates({}))

    assert "NAT_INTERFACE_BINDING_UNKNOWN" not in edge
    assert "nat:pat" in edge
    assert "NAT_INTERFACE_BINDING_UNKNOWN" in plain


class _SessionGates(_Gates):
    """`_Gates` on a pinned session, as `GraphGates` is."""

    def __init__(self, exits, session, calls):
        super().__init__(exits)
        self.session, self.calls = session, calls


def test_the_uplink_facts_are_read_once_per_pinned_session():
    """A failure scenario or a change candidate builds new gates (and an overlay
    session) on the same pinned session: the uplink facts are read once."""
    from tests.test_impact_evaluate import _changes

    from hst.impact.evaluate import _OverlaySession

    class _Session:
        pass

    pinned, calls = _Session(), []
    exits = {"192.0.2.254": _exit(None)}
    for session in (pinned, _OverlaySession(pinned, _changes()), _OverlaySession(pinned, _changes())):
        _one_default(_SessionGates(exits, session, calls))
    assert [call[3] for call in calls] == ["192.0.2.254"]
    # another pinned session reads again
    _one_default(_SessionGates(exits, _Session(), calls))
    assert len(calls) == 2


def test_a_round_trip_names_its_forward_edge_with_the_forward_walks_identity():
    exits = (tuple(le._exit("site-zone", block="dc-edge").items()),)
    edge = _state(NEXT_HOP_EDGE)
    forward = SimpleNamespace(
        by_choice=(
            SimpleNamespace(
                assignment=ChoiceAssignment("only"),
                terminal_reaches=(TerminalReach(edge, "permit", None, exits),),  # type: ignore[arg-type]
                scoped_gaps=(),
            ),
        ),
        manifest_digest="a" * 64,
        model_fingerprint="forward-fp",
        request_id="req",
    )
    answer = _symbolic_answer([TerminalReach(_state("delivery:vrf:r1:10.0.0.0/24"), "permit", None)], [])  # type: ignore[arg-type]
    answer.members["app"].forward = forward
    answer.members["app"].request_id = "req:reply"
    plain = _symbolic_answer([TerminalReach(_state("delivery:vrf:r1:10.0.0.0/24"), "permit", None)], [])  # type: ignore[arg-type]
    rows = symbolic_results._evidence(answer, plain)["items"]  # type: ignore[arg-type]
    before = [row for row in rows if row["side"] == "before"]

    assert len(before) == 2 and not any("left_estate" in row for row in before[:1])
    row = before[1]
    assert (row["model_fingerprint"], row["request_id"], row["artifact_root"]) == (
        "forward-fp",
        "req",
        "before/member/app/forward/choice/0/terminal/0",
    )
    assert row["outcome"] == "permit" and row["left_estate"] == [le._exit("site-zone", block="dc-edge")]
    assert [r["artifact_root"] for r in rows if r["side"] == "after"] == [
        "after/member/app/choice/0/terminal/0"
    ]


# --- the estate is what the tracer's rule says (`estate_prefixes`) ------------------------------

# per family: the uplink, the default's next hop, a source LAN, a destination
# another device routes (r2, static), a private one nothing routes, a public one
_FAMILIES = {
    4: {
        "wan": ("192.0.2.0/24", "192.0.2.1"),
        "hop": "192.0.2.254",
        "default": "0.0.0.0/0",
        "lan": ("10.0.0.0/24", "10.0.0.10"),
        "routed": ("198.18.0.0/24", "198.18.0.9", "203.0.113.9"),
        "private": "10.99.0.9",
        "public": "198.51.100.7",
    },
    6: {
        "wan": ("2001:db8:0:1::/64", "2001:db8:0:1::1"),
        "hop": "2001:db8:0:1::ff",
        "default": "::/0",
        "lan": ("2001:db8:100::/64", "2001:db8:100::10"),
        "routed": ("2001:db8:5000::/48", "2001:db8:5000::9", "2001:db8:2::9"),
        "private": "fd00:99::9",
        "public": "2001:db8:ffff::77",
    },
}


def _symbolic_takes_edge(family, destination):
    """Whether the symbolic model sends `destination` to the permit at the
    recognized next-hop edge."""
    f = _FAMILIES[family]
    network = replace(nc._network(), gates=_Gates({f["hop"]: _exit(None)}))
    if family == 6:
        network = replace(
            network,
            interfaces=(
                *network.interfaces,
                Interface("r1", "if:r1:wan6", "wan6", "c1", (f["wan"][0],), (f["wan"][1],)),
                Interface("r1", "if:r1:lan6", "lan6", "c1", (f["lan"][0],), ("2001:db8:100::1",)),
                Interface("r2", "if:r2:lan6", "lan6", "c2", ("2001:db8:2::/64",), ("2001:db8:2::1",)),
            ),
        )
        network.routing.connected.extend(
            [
                {"context_uid": "c1", "prefix": f["wan"][0], "interface": "wan6"},
                {"context_uid": "c1", "prefix": f["lan"][0], "interface": "lan6"},
                {"context_uid": "c2", "prefix": "2001:db8:2::/64", "interface": "lan6"},
            ]
        )
    prefix, _inside, via = f["routed"]
    network.routing.static.extend(
        [
            {"context_uid": "c1", "prefix": f["default"], "next_hop": f["hop"]},
            {"context_uid": "c2", "prefix": prefix, "next_hop": via},
        ]
    )
    request = RequestSet(
        "x",
        nc._ivals(f["lan"][1]),
        "s",
        (Member("s", nc._ivals(destination)),),
        member("s"),
        source_context="c1",
    )
    model = normalize_network(
        network, nc._contexts_graph(c1=True, c2=True), request, request.members[0], "estate"
    )
    nodes = {n.key.location: n for n in model.nodes}
    split = next(n for loc, n in nodes.items() if loc.startswith("estate-edge-split:"))
    held = split.edges[0].predicate
    address = int(ipaddress.ip_address(destination))
    edge = next(n for loc, n in nodes.items() if loc.startswith("estate-edge:"))
    assert edge.terminal == "permit" and edge.left_estate
    return not any(atom.value <= address <= atom.other for atom in held.terms)


@pytest.mark.parametrize("family", [4, 6])
def test_symbolic_only_an_internet_destination_takes_the_recognized_edge(family):
    f = _FAMILIES[family]
    assert _symbolic_takes_edge(family, f["public"]) is True
    # another collected device routes it: a route missing here, not the internet
    assert _symbolic_takes_edge(family, f["routed"][1]) is False
    # private space nothing routes
    assert _symbolic_takes_edge(family, f["private"]) is False


def _legacy(family, destination, uplink):
    """The impact evaluator's answer from r1 by its default to an unheld next hop."""
    from hst.path.addrsets import _intervals

    f = _FAMILIES[family]
    prefix, _inside, via = f["routed"]
    if family == 4:
        network = le._network(le.NEXT_HOP)
        sources = le.estate.CLIENTS
    else:
        inp = le.estate._routing(bgp=False, static=[le.estate._static("::/0", "2001:db8:9::2")])
        inp = replace(
            inp,
            connected=[
                *inp.connected,
                le.estate._connected(le.estate.VRF_R1, "2001:db8:9::/64", "eth3"),
                le.estate._connected(le.estate.VRF_R1, f["lan"][0], "eth0"),
                le.estate._connected(le.estate.VRF_B, "2001:db8:2::/64", "eth1"),
            ],
        )
        interfaces = (
            *le.estate._interfaces(),
            ev.Interface(
                le.estate.R1, le.WAN_IF, "eth3", le.estate.VRF_R1, ("2001:db8:9::/64",), ("2001:db8:9::1",)
            ),
            ev.Interface(
                le.estate.R1, "if:r1-eth0-6", "eth0", le.estate.VRF_R1, (f["lan"][0],), ("2001:db8:100::1",)
            ),
            ev.Interface(
                le.estate.B, "if:b-eth1-6", "eth1", le.estate.VRF_B, ("2001:db8:2::/64",), ("2001:db8:2::2",)
            ),
        )
        network = le.estate._network(routing=inp, interfaces=interfaces)
        sources = tuple(_intervals([f["lan"][0]]))
    network.routing.static.append(le.estate._static(prefix, via, context_uid=le.estate.VRF_B))
    answer = ev.answer(network, le.estate._request(dst=destination, sources=sources))
    return le._terminal(answer)


@pytest.mark.parametrize("family", [4, 6])
def test_the_impact_evaluator_passes_only_an_internet_destination_at_the_edge(graph, family):
    f = _FAMILIES[family]
    le._answers(graph, le._row(zone="internet"))
    explanation, step = _legacy(family, f["public"], None)
    assert explanation.outcome == ev.HOLDS and step.data["left_estate"]["basis"] == "site-zone"
    for destination in (f["routed"][1], f["private"]):
        explanation, step = _legacy(family, destination, None)
        assert explanation.outcome == ev.NOT_ESTABLISHED, destination
        assert step.kind == "unowned" and "left_estate" not in step.data, destination


# --- the reply groups, with stand-in sets (no native backend) ------------------------------------


class _Set(frozenset):
    """A stand-in `PacketSet`: a set of (original, current) packet ids; the
    original bank is the id itself."""

    def intersect(self, other):
        return _Set(self & other)

    def union(self, other):
        return _Set(self | other)

    def subtract(self, other):
        return _Set(self - other)

    def is_empty(self):
        return not self


def _choice(terminals, lower):
    return SimpleNamespace(
        bounds=SimpleNamespace(lower=_Set(lower)),
        terminal_reaches=tuple(TerminalReach(state, "permit", _Set(packets)) for state, packets in terminals),  # type: ignore[arg-type]
    )


def test_a_choice_with_one_terminal_walks_its_reply_from_that_terminals_entries_only():
    """An equal-cost choice reaches one uplink: its reply is walked from that
    uplink's entries only, not from the other's."""
    from hst.analysis_model.session_walk import _reply_groups

    a, b = _state("estate-edge:a"), _state("estate-edge:b")
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class _Model:
        entries: tuple[str, ...]

    model = _Model(("in_a", "in_b"))
    groups = _reply_groups(model, _choice([(a, {1, 2})], {1, 2}), (a, b))  # type: ignore[arg-type]

    assert [(g[0].entries, set(g[1])) for g in groups] == [(("in_a",), {1, 2})]
    # a terminal that owns every entry, and no binding at all, walk the model itself
    assert _reply_groups(model, _choice([(a, {1})], {1}), (a, a))[0][0] is model  # type: ignore[arg-type]
    assert _reply_groups(model, _choice([(a, {1}), (b, {2})], {1, 2}), None)[0][0] is model  # type: ignore[arg-type]


def test_what_two_reply_groups_share_is_never_decided_from_their_union():
    from hst.analysis_model.session_walk import _overlap

    empty = _Set()
    assert _overlap([_Set({1, 2})], empty) == empty
    assert _overlap([_Set({1, 2}), _Set({3})], empty) == empty
    assert _overlap([_Set({1, 2}), _Set({2, 3}), _Set({3, 4})], empty) == {2, 3}


# --- the interface-only edge (PPPoE) -------------------------------------------------------------


class _UplinkGates(_Gates):
    """Gates that recognize an edge by its egress interface (a WAN link on the
    PPPoE uplink), whatever the next hop."""

    def __init__(self, uplinks):
        super().__init__({})
        self.uplinks = uplinks

    def estate_exit(self, device_uid, context_uid, route, out_if):
        self.calls.append((device_uid, context_uid, route["cidr"], route["next_hop"], out_if.uid))
        return _exit(route["next_hop"]) if out_if.uid in self.uplinks else None


def _interface_only(destination, interface="wan"):
    """r1 (c1) with an interface-only default by `interface`; r2 serves
    172.20.0.0/24; the uplink `wan` is recognized (a WAN link), a tunnel
    `wg0` is not."""
    network = replace(nc._network(), gates=_UplinkGates({"if:r1:wan"}))
    network = replace(
        network,
        interfaces=(
            *network.interfaces,
            Interface("r1", "if:r1:wg0", "wg0", "c1", ("10.255.0.0/30",), ("10.255.0.1",)),
            Interface("r2", "if:r2:far", "far", "c2", ("172.20.0.0/24",), ("172.20.0.1",)),
        ),
    )
    network.routing.connected.extend(
        [
            {"context_uid": "c1", "prefix": "10.255.0.0/30", "interface": "wg0"},
            {"context_uid": "c2", "prefix": "172.20.0.0/24", "interface": "far"},
        ]
    )
    network.routing.static.append({"context_uid": "c1", "prefix": "0.0.0.0/0", "interface": interface})
    request = RequestSet(
        "x",
        nc._ivals("10.0.0.10"),
        "s",
        (Member("s", nc._ivals(destination)),),
        member("s"),
        source_context="c1",
    )
    model = normalize_network(
        network, nc._contexts_graph(c1=True, c2=True), request, request.members[0], "estate"
    )
    return {n.key.location: n for n in model.nodes}


def _reaches(nodes, destination):
    """The terminal location `destination` takes behind the recognized edge's split."""
    split = nodes["estate-delivery-split:c1:0.0.0.0/0"]
    address = int(ipaddress.ip_address(destination))
    inside = any(atom.value <= address <= atom.other for atom in split.edges[0].predicate.terms)
    return split.edges[0 if inside else 1].target.location


def test_the_pppoe_edge_passes_for_a_public_destination_with_the_marker():
    nodes = _interface_only("198.51.100.7")
    target = _reaches(nodes, "198.51.100.7")
    assert target == "estate-delivery:c1:0.0.0.0/0"
    assert nodes[target].terminal == "permit" and nodes[target].left_estate


@pytest.mark.parametrize(
    "destination", ["10.99.0.9", "172.20.0.9"], ids=["private-no-route", "served-by-another-device"]
)
def test_the_pppoe_edge_leaves_an_estate_destination_undecided_with_no_marker(destination):
    nodes = _interface_only(destination)
    target = _reaches(nodes, destination)
    assert target == "terminal:estate-destination:c1:0.0.0.0/0"
    assert (nodes[target].terminal, nodes[target].complete, nodes[target].left_estate) == (
        "unknown",
        False,
        (),
    )


def test_a_tunnel_interface_route_that_is_no_recognized_edge_delivers_as_today():
    nodes = _interface_only("198.51.100.7", interface="wg0")
    assert not any(loc.startswith(("estate-", "terminal:estate-destination")) for loc in nodes)
    delivery = nodes["delivery:c1:0.0.0.0/0"]
    assert (delivery.terminal, delivery.left_estate, delivery.key.binding_scope) == (
        "permit",
        (),
        ("reply-ingress:if:r1:wg0",),
    )


# --- the estate's prefixes: uplinks, cost ---------------------------------------------------------


def _uplink_network(**facts):
    """r1 with a DHCP uplink whose lease subnet is public (198.51.100.0/24),
    and `facts` on that interface."""
    network = nc._network()
    wan = Interface("r1", "if:r1:dhcp", "dhcp", "c1", ("198.51.100.0/24",), ("198.51.100.20",), **facts)
    network = replace(network, interfaces=(*network.interfaces, wan))
    network.routing.connected.append({"context_uid": "c1", "prefix": "198.51.100.0/24", "interface": "dhcp"})
    # the DHCP default route of r1 leaves by that interface to the provider
    network.routing.static.append({"context_uid": "c1", "prefix": "0.0.0.0/0", "next_hop": "198.51.100.1"})
    return network


def _in_estate(network, address):
    value = int(ipaddress.ip_address(address))
    return any(af == 4 and low <= value <= high for af, low, high in network.estate_prefixes)


@pytest.mark.parametrize(
    ("facts", "provider"),
    [
        pytest.param({"link_kinds": ("dhcp",)}, True, id="wan-link"),
        pytest.param({"default_origin": "dhcp"}, True, id="access-client-default"),
        pytest.param({"link_kinds": ("mpls",)}, False, id="mpls"),
        pytest.param({}, False, id="no-facts"),
    ],
)
def test_an_uplinks_provider_subnet_is_not_the_estates(facts, provider):
    """The provider's transfer network on an uplink (the tracer's rule,
    `uplinks`: an exit is recognized by a default route out of the interface)
    is left out of the estate; an MPLS link or a plain interface keeps its
    prefix in it."""
    network = _uplink_network(**facts)
    assert _in_estate(network, "198.51.100.30") is not provider
    assert _in_estate(network, "10.0.0.5")  # a LAN stays the estate's


def test_a_zone_internet_device_leaves_out_the_prefix_its_default_leaves_by():
    network = _uplink_network(site_zone="internet")
    assert not _in_estate(network, "198.51.100.30")
    assert _in_estate(_uplink_network(site_zone="external"), "198.51.100.30")


def test_a_derived_network_with_the_same_rows_shares_the_estates_prefixes():
    parent = nc._network()
    child = replace(parent, baseline=parent)
    assert child.estate_prefixes is parent.estate_prefixes


def test_the_impact_walk_computes_the_estates_prefixes_only_at_a_recognized_edge(graph):
    le._answers(graph)
    network = le._network(le.NEXT_HOP)
    ev.answer(network, le.estate._request(dst=le.INTERNET))
    assert "estate_prefixes" not in network.__dict__
    le._answers(graph, le._row(zone="internet"))
    network = le._network(le.NEXT_HOP)
    ev.answer(network, le.estate._request(dst=le.INTERNET))
    assert "estate_prefixes" in network.__dict__


# --- by which uplink the reply returns -----------------------------------------------------------


def _uplinks(*states, edges):
    """Stand-in reply and forward models: one reply entry per terminal in
    `states`; `edges` are the forward terminals at the estate's edge."""
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class _Reply:
        entries: tuple[str, ...]

    reply = _Reply(tuple(f"in:{state.location}" for state in states))
    forward = SimpleNamespace(
        nodes=tuple(
            SimpleNamespace(key=state, left_estate=_OBJECT if state in edges else ()) for state in states
        )
    )
    return reply, forward


CTX_KEY = _state("x").context
_A = StateKey("estate-edge:c1:0.0.0.0/0:192.0.2.1", CTX_KEY, binding_scope=("reply-ingress:a",))
_B = StateKey("estate-edge:c1:0.0.0.0/0:192.0.2.2", CTX_KEY, binding_scope=("reply-ingress:b",))
_LAN = StateKey("delivery:c1:10.0.0.0/24", CTX_KEY, binding_scope=("reply-ingress:lan",))


def test_with_two_uplinks_and_no_source_nat_the_reply_may_return_by_the_other():
    from hst.analysis_model.session_walk import _other_uplinks

    reply, forward = _uplinks(_A, _B, _LAN, edges={_A, _B})
    found = _other_uplinks(reply, forward, _A, _Set({1}), (_A, _B, _LAN), {})  # type: ignore[arg-type]
    assert [(state, model.entries) for state, model in found] == [(_B, (f"in:{_B.location}",))]


def test_a_source_nat_to_the_uplinks_own_address_returns_by_that_uplink(monkeypatch):
    from hst.analysis_model import session_walk

    monkeypatch.setattr(session_walk, "_translated", lambda part, ranges: ranges == ((4, 1, 1),))
    reply, forward = _uplinks(_A, _B, edges={_A, _B})
    assert session_walk._other_uplinks(reply, forward, _A, _Set({1}), (_A, _B), {"a": ((4, 1, 1),)}) == []  # type: ignore[arg-type]
    # a translation to another address (a pool) is not the uplink's: the stricter case
    assert len(session_walk._other_uplinks(reply, forward, _A, _Set({1}), (_A, _B), {"a": ((4, 9, 9),)})) == 1  # type: ignore[arg-type]


def test_one_uplink_or_a_delivery_inside_the_estate_keeps_its_own_entry():
    """The owner's shape (one PPPoE uplink with masquerade) and a LAN delivery:
    nothing else to walk from."""
    from hst.analysis_model.session_walk import _other_uplinks

    reply, forward = _uplinks(_A, _LAN, edges={_A})
    assert _other_uplinks(reply, forward, _A, _Set({1}), (_A, _LAN), {}) == []  # type: ignore[arg-type]
    reply, forward = _uplinks(_A, _B, _LAN, edges={_A, _B})
    assert _other_uplinks(reply, forward, _LAN, _Set({1}), (_A, _B, _LAN), {}) == []  # type: ignore[arg-type]
    assert _other_uplinks(reply, forward, _A, _Set({1}), None, {}) == []  # type: ignore[arg-type]


def test_the_uplink_addresses_are_those_of_the_bound_interfaces():
    from hst.analysis_model.network_session import _uplink_addresses

    network = nc._network()
    found = _uplink_addresses(
        network, (StateKey("estate-edge:x", CTX_KEY, binding_scope=("reply-ingress:if:r1:wan",)),)
    )
    value = int(ipaddress.ip_address("192.0.2.1"))
    assert found == {"if:r1:wan": ((4, value, value),)}


def test_an_uplink_needs_a_default_route_out_of_it():
    """The tracer's rule (Update 3): when the device has a default route, a WAN
    link alone makes no uplink, the default must leave by the interface. When
    the device has no default route at all in what the engine reads, the
    first WAN link (not MPLS) or the access client's mark decides."""
    network = nc._network()
    wan = Interface(
        "r1", "if:r1:dhcp", "dhcp", "c1", ("198.51.100.0/24",), ("198.51.100.20",), link_kinds=("dhcp",)
    )
    network = replace(network, interfaces=(*network.interfaces, wan))
    # no default route on r1: the WAN link decides
    assert not _in_estate(network, "198.51.100.30")
    # a default route of r1 that leaves by another interface: no uplink
    network = replace(network, interfaces=network.interfaces)
    network.routing.static.append({"context_uid": "c1", "prefix": "0.0.0.0/0", "next_hop": "192.0.2.254"})
    assert _in_estate(network, "198.51.100.30")
