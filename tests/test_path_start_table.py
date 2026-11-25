"""`trace(start_table=...)`: a trace that starts in one VRF of one device. The
first route lookup is in that VRF, and the source address does not select the
start."""

import pytest
from tests.test_path_trace import GW, FakeGraph, _route

from hst import path

L3DOM = "inventory:acme-emea:hosting"
LEAF_A = {
    **GW,
    "l3dom": L3DOM,
    "anchor": "vrf:dev:leaf-a:hosting",
    "if_uid": "if:leaf-a:vlan10",
    "if_name": "Vlan10",
    "dev_uid": "dev:leaf-a",
    "dev_name": "leaf-a",
}
LEAF_B = {
    **LEAF_A,
    "anchor": "vrf:dev:leaf-b:hosting",
    "if_uid": "if:leaf-b:vlan10",
    "dev_uid": "dev:leaf-b",
    "dev_name": "leaf-b",
}
BORDER = "vrf:dev:border:hosting"
TABLES = {
    LEAF_A["anchor"]: {
        "uid": LEAF_A["anchor"],
        "name": "hosting",
        "dev_uid": "dev:leaf-a",
        "dev_name": "leaf-a",
    },
    LEAF_B["anchor"]: {
        "uid": LEAF_B["anchor"],
        "name": "hosting",
        "dev_uid": "dev:leaf-b",
        "dev_name": "leaf-b",
    },
    BORDER: {"uid": BORDER, "name": "hosting", "dev_uid": "dev:border", "dev_name": "border"},
}
tracemod = __import__("importlib").import_module("hst.path.trace")


@pytest.fixture
def graph(monkeypatch):
    g = FakeGraph()
    g.default_tables = {
        LEAF_A["if_uid"]: {"uid": LEAF_A["anchor"]},
        LEAF_B["if_uid"]: {"uid": LEAF_B["anchor"]},
        "if:uplink": {"uid": BORDER},
    }
    g.routes = {
        LEAF_A["anchor"]: [_route("0.0.0.0/0", egress="leaf-a-uplink", next_hop="192.0.2.1")],
        LEAF_B["anchor"]: [_route("0.0.0.0/0", egress="leaf-b-uplink", next_hop="192.0.2.2")],
        BORDER: [
            _route("10.0.0.0/8", egress="uplink", next_hop="192.0.2.9"),
            _route("203.0.113.0/24", egress="internet", next_hop="198.51.100.1"),
        ],
    }
    seen = []

    def read(session, query, **params):
        seen.append(query)
        if query is tracemod._START_TABLES_QUERY:
            return [{"uid": t["uid"], "name": t["name"], "device": t["dev_name"]} for t in TABLES.values()]
        return g.read(query, **params)

    def read_one(session, query, **params):
        seen.append(query)
        if query is tracemod._START_TABLE_QUERY:
            return TABLES.get(params["u"])
        return g.read_one(query, **params)

    monkeypatch.setattr(path, "_read", read)
    monkeypatch.setattr(path, "_read_one", read_one)
    g.seen_all = seen
    return g


def _devices(result):
    return [h["uid"] for h in result["hops"] if h["kind"] == "Device"]


def test_without_a_start_the_same_prefix_on_two_leaves_is_ambiguous(graph):
    result = path.trace(None, "10.0.0.0/24", "203.0.113.5", gateways=[LEAF_A, LEAF_B])
    assert "ambiguous" in result["verdict"]


def test_a_start_vrf_with_a_gateway_for_the_source_starts_on_that_gateway(graph):
    result = path.trace(
        None, "10.0.0.0/24", "203.0.113.5", gateways=[LEAF_A, LEAF_B], start_table=LEAF_B["anchor"]
    )

    assert "ambiguous" not in result["verdict"]
    assert _devices(result) == ["dev:leaf-b"]
    assert {leg["egress"] for leg in result["legs"]} == {"leaf-b-uplink"}
    assert result["notes"][0] == "trace starts in VRF hosting on leaf-b"


def test_a_start_vrf_with_no_gateway_for_the_source_takes_the_route_back_to_it(graph):
    result = path.trace(None, "10.0.0.5", "203.0.113.5", gateways=[LEAF_A, LEAF_B], start_table=BORDER)

    assert _devices(result) == ["dev:border"]
    assert {leg["egress"] for leg in result["legs"]} == {"internet"}
    assert result["notes"][0] == (
        "trace starts in VRF hosting on border; "
        "ingress uplink is the interface of the route 10.0.0.0/8 to the source"
    )
    # the source is behind a routed hop: no endpoint or L2 walk is drawn
    assert not any(h["kind"] in ("Endpoint", "Port") for h in result["hops"])


def test_a_route_back_with_only_a_next_hop_is_resolved_through_it(graph):
    graph.routes[BORDER] = [
        _route("10.0.0.0/8", next_hop="192.0.2.9"),
        _route("192.0.2.0/24", egress="uplink"),
        _route("203.0.113.0/24", egress="internet", next_hop="198.51.100.1"),
    ]

    result = path.trace(None, "10.0.0.5", "203.0.113.5", gateways=[LEAF_A, LEAF_B], start_table=BORDER)

    assert "ingress uplink is the interface of the route 10.0.0.0/8" in result["notes"][0]
    assert {leg["egress"] for leg in result["legs"]} == {"internet"}


def test_no_route_back_to_the_source_stops_with_the_reason(graph):
    graph.routes[BORDER] = [_route("203.0.113.0/24", egress="internet", next_hop="198.51.100.1")]

    result = path.trace(None, "10.0.0.5", "203.0.113.5", gateways=[LEAF_A, LEAF_B], start_table=BORDER)

    assert result["legs"] == []
    assert result["verdict"] == (
        "VRF hosting on border has no route to the source 10.0.0.5; the ingress interface is not known"
    )


def test_an_unknown_start_vrf_stops_with_the_reason(graph):
    result = path.trace(None, "10.0.0.5", "203.0.113.5", gateways=[LEAF_A], start_table="vrf:dev:none:x")

    assert result["legs"] == []
    assert result["verdict"] == "no VRF 'vrf:dev:none:x' that belongs to a device in this run"


def test_start_table_and_src_context_cannot_both_be_set(graph):
    with pytest.raises(ValueError, match="cannot both be set"):
        path.trace(None, "10.0.0.5", "203.0.113.5", gateways=[LEAF_A], start_table=BORDER, src_context=BORDER)


def test_start_tables_lists_each_vrf_with_its_device(graph):
    session = type("Pinned", (), {"cts": 1000})()
    assert path.start_tables(session) == [
        {"uid": LEAF_A["anchor"], "name": "hosting", "device": "leaf-a"},
        {"uid": LEAF_B["anchor"], "name": "hosting", "device": "leaf-b"},
        {"uid": BORDER, "name": "hosting", "device": "border"},
    ]


def test_a_start_vrf_trace_can_ask_for_the_reply(graph):
    result = path.trace(
        None,
        "10.0.0.0/24",
        "203.0.113.5",
        gateways=[LEAF_A, LEAF_B],
        start_table=LEAF_B["anchor"],
        reply=True,
    )

    assert set(result) >= {"forward", "reply", "asymmetric"}
    assert result["forward"]["notes"][0] == "trace starts in VRF hosting on leaf-b"
