import pytest
from tests.test_path_start_table import BORDER, L3DOM, LEAF_A, LEAF_B, TABLES, graph, tracemod  # noqa: F401
from tests.test_path_trace import _route

from hst import path


@pytest.fixture
def vrf_graph(graph, monkeypatch):  # noqa: F811
    inner = path._read

    def read(session, query, **params):
        if query is tracemod._NAMED_TABLES_QUERY:
            named = [t for t in TABLES.values() if t["name"] == params["name"]]
            return sorted(named, key=lambda t: (t["dev_name"], t["uid"]))
        if query is tracemod._RPF_BOUNDS_QUERY:
            # every prefix of each table's routes; the tracer keeps the ones
            # that cover the source, as it does for a prefix with no keys
            return [
                {"table_uid": u, "cidrs": [r["cidr"] for r in graph.routes.get(u, [])]}
                for u in params["tables"]
            ]
        return inner(session, query, **params)

    monkeypatch.setattr(path, "_read", read)
    return graph


def _devices(result):
    return [h["uid"] for h in result["hops"] if h["kind"] == "Device"]


def test_start_vrfs_lists_each_name_once_with_its_device_count(vrf_graph):
    session = type("Pinned", (), {"cts": 1000})()
    assert path.start_vrfs(session) == [{"name": "hosting", "devices": 3}]


def test_a_host_starts_on_the_leaf_it_is_on(vrf_graph):
    vrf_graph.sources = [
        {"anchor": LEAF_B["anchor"], "l3dom": L3DOM, "owned": True, "ip_uid": "ip:b", "ep_uid": "ep:b"}
    ]

    result = path.trace_from_vrf(None, "10.0.0.5", "203.0.113.5", "hosting", gateways=[LEAF_A, LEAF_B])

    assert _devices(result) == ["dev:leaf-b"]
    assert result["notes"][0] == "trace starts in VRF hosting on leaf-b"


def test_a_prefix_on_two_leaves_is_traced_from_each(vrf_graph):
    result = path.trace_from_vrf(None, "10.0.0.0/24", "203.0.113.5", "hosting", gateways=[LEAF_A, LEAF_B])

    assert set(_devices(result)) == {"dev:leaf-a", "dev:leaf-b"}
    assert result["notes"][0] == (
        "VRF hosting starts the trace on 2 devices (hosting on leaf-a, hosting on leaf-b); each is traced"
    )
    assert {h["domain"] for h in result["hops"]} == {"hosting on leaf-a", "hosting on leaf-b"}
    assert "[hosting on leaf-a]" in result["verdict"] and "[hosting on leaf-b]" in result["verdict"]


def test_with_no_gateway_the_most_specific_route_back_picks_the_start(vrf_graph):
    result = path.trace_from_vrf(None, "10.9.9.5", "203.0.113.5", "hosting", gateways=[LEAF_A, LEAF_B])

    assert _devices(result) == ["dev:border"]
    assert result["notes"][0] == (
        "no gateway of VRF hosting holds the source 10.9.9.5; "
        "hosting on border has the most specific route back to it, a /8"
    )
    assert result["notes"][1].startswith("trace starts in VRF hosting on border; ingress uplink")


def test_routes_back_of_equal_length_all_start_the_trace(vrf_graph):
    result = path.trace_from_vrf(None, "172.16.0.5", "203.0.113.5", "hosting", gateways=[LEAF_A, LEAF_B])

    assert set(_devices(result)) == {"dev:leaf-a", "dev:leaf-b"}
    assert result["notes"][1] == (
        "no gateway of VRF hosting holds the source 172.16.0.5; "
        "hosting on leaf-a, hosting on leaf-b have the most specific route back to it, a /0"
    )


def _routes_reads(monkeypatch):
    """The tables `_ROUTES_QUERY` is read for, in order."""
    seen: list[str] = []
    inner = path._read

    def read(session, query, **params):
        if query is tracemod._ROUTES_QUERY:
            seen.append(params["vrf"])
        return inner(session, query, **params)

    monkeypatch.setattr(path, "_read", read)
    return seen


def test_with_no_gateway_only_the_tables_that_can_hold_the_best_route_back_are_read(vrf_graph, monkeypatch):
    seen = _routes_reads(monkeypatch)

    found = tracemod.vrf_starts(None, "hosting", "10.9.9.5", gateways=[LEAF_A, LEAF_B])

    assert [t["uid"] for t in found.starts] == [BORDER]
    assert seen == [BORDER]


def test_a_table_whose_longest_route_back_is_a_discard_does_not_hide_the_next_length(vrf_graph, monkeypatch):
    vrf_graph.routes[BORDER] = [_route("10.9.0.0/16", discard="Null0")]
    seen = _routes_reads(monkeypatch)

    found = tracemod.vrf_starts(None, "hosting", "10.9.9.5", gateways=[LEAF_A, LEAF_B])

    assert [t["uid"] for t in found.starts] == [LEAF_A["anchor"], LEAF_B["anchor"]]
    assert found.note.endswith("a /0")
    assert seen[0] == BORDER and set(seen[1:]) == {LEAF_A["anchor"], LEAF_B["anchor"]}

    vrf_graph.routes[LEAF_A["anchor"]] = []
    seen.clear()
    found = tracemod.vrf_starts(None, "hosting", "10.9.9.5", gateways=[LEAF_A, LEAF_B])
    assert [t["uid"] for t in found.starts] == [LEAF_B["anchor"]]
    assert LEAF_A["anchor"] not in seen


def test_a_reply_is_refused_for_two_starts(vrf_graph):
    with pytest.raises(ValueError, match="reply=True is not supported for VRF hosting"):
        path.trace_from_vrf(
            None, "10.0.0.0/24", "203.0.113.5", "hosting", gateways=[LEAF_A, LEAF_B], reply=True
        )


def test_a_reply_is_traced_for_one_start(vrf_graph):
    vrf_graph.sources = [
        {"anchor": LEAF_B["anchor"], "l3dom": L3DOM, "owned": True, "ip_uid": "ip:b", "ep_uid": "ep:b"}
    ]

    result = path.trace_from_vrf(
        None, "10.0.0.5", "203.0.113.5", "hosting", gateways=[LEAF_A, LEAF_B], reply=True
    )

    assert set(result) >= {"forward", "reply", "asymmetric"}


def test_an_unknown_vrf_name_stops_with_the_reason(vrf_graph):
    result = path.trace_from_vrf(None, "10.0.0.5", "203.0.113.5", "nope", gateways=[LEAF_A, LEAF_B])

    assert result["legs"] == []
    assert result["verdict"] == "no VRF named 'nope' in this run"


def test_no_gateway_and_no_route_back_stops_with_the_reason(vrf_graph):
    vrf_graph.routes = {uid: [] for uid in vrf_graph.routes}

    result = path.trace_from_vrf(None, "172.16.0.5", "203.0.113.5", "hosting", gateways=[LEAF_A, LEAF_B])

    assert result["legs"] == []
    assert result["verdict"] == "VRF hosting has no gateway for the source 172.16.0.5 and no route back to it"


def test_one_start_is_traced_with_its_vrf_as_the_start_table(vrf_graph, monkeypatch):
    seen = []
    real = tracemod.trace

    def spy(*args, **kwargs):
        seen.append(kwargs.get("start_table"))
        return real(*args, **kwargs)

    monkeypatch.setattr(tracemod, "trace", spy)
    path.trace_from_vrf(None, "10.9.9.5", "203.0.113.5", "hosting", gateways=[LEAF_A, LEAF_B])

    assert seen[0] == BORDER


def test_the_name_matches_exactly_case_included(vrf_graph):
    result = path.trace_from_vrf(None, "10.0.0.5", "203.0.113.5", "HOSTING", gateways=[LEAF_A, LEAF_B])

    assert result["legs"] == []
    assert result["verdict"] == "no VRF named 'HOSTING' in this run"


def test_the_longest_gateway_prefix_of_the_source_picks_the_start(vrf_graph):
    wide = {**LEAF_A, "cidr": "10.0.0.0/16"}
    narrow = {**LEAF_B, "cidr": "10.0.0.0/24"}

    result = path.trace_from_vrf(None, "10.0.0.0/24", "203.0.113.5", "hosting", gateways=[wide, narrow])

    assert _devices(result) == ["dev:leaf-b"]


def test_a_source_that_is_no_address_gets_the_input_error(vrf_graph):
    plain = path.trace(None, "10.0.0.300", "203.0.113.5", gateways=[LEAF_A, LEAF_B])
    result = path.trace_from_vrf(None, "10.0.0.300", "203.0.113.5", "hosting", gateways=[LEAF_A, LEAF_B])

    assert result["verdict"] == plain["verdict"]
