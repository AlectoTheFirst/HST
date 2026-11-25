import json

import pytest

import hst.app.tables as tables
from hst.app.tables import (
    MAX_ROWS,
    UNPINNED_QUERY,
    QueryRejected,
    ResultTooLarge,
    check_pinned,
    check_readonly,
    rows_to_table,
    run_readonly,
)
from hst.core import Settings


def test_rows_to_table_shapes_named_columns():
    out = rows_to_table(["a", "b"], [{"a": 1, "b": "x"}, {"a": 2, "b": None}])
    assert out["columns"] == ["a", "b"]
    assert out["data"] == [{"row": [1, "x"]}, {"row": [2, None]}]
    assert out["truncated"] is False


def test_rows_to_table_survives_unjsonable_values():
    class Odd:
        def __str__(self):
            return "odd!"

    out = rows_to_table(["v"], [{"v": Odd()}])
    assert out["data"][0]["row"] == ["odd!"]
    json.dumps(out)


def test_rows_to_table_caps_rows():
    out = rows_to_table(["n"], [{"n": i} for i in range(MAX_ROWS + 7)])
    assert len(out["data"]) == MAX_ROWS and out["truncated"] is True


# --- run_readonly against a stub driver ----------------------------------------


class _Record:
    def __init__(self, data):
        self._data = data

    def data(self):
        # the driver flattens nodes to their properties here
        return {k: (dict(v) if hasattr(v, "element_id") else v) for k, v in self._data.items()}

    def values(self):
        return list(self._data.values())


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def __iter__(self):
        return iter(_Record(r) for r in self._rows)

    def keys(self):
        return list(self._rows[0]) if self._rows else []

    def consume(self):
        return None

    def data(self):
        # the pointer read (core.cycle.current_ts) calls .data() on the result
        return list(self._rows)


class _Tx:
    def __init__(self, rows, seen):
        self._rows, self._seen = rows, seen

    def run(self, query, *args, **kwargs):
        self._seen["args"], self._seen["kwargs"] = args, kwargs
        return _Result(self._rows)


class _Session:
    def __init__(self, rows, seen, current=None):
        self._rows, self._seen, self._current = rows, seen, current

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        # the pointer read run_readonly issues before the managed read, the same
        # autocommit shape core.cycle.current_ts_or_none uses
        self._seen["pointer_calls"] = self._seen.get("pointer_calls", 0) + 1
        rows = [{"current": self._current}] if self._current is not None else []
        return _Result(rows)

    def execute_read(self, work):
        return work(_Tx(self._rows, self._seen))


def _stub_session(monkeypatch, rows, current=None):
    seen = {}
    monkeypatch.setattr(tables.dbmod, "session", lambda settings, **kwargs: _Session(rows, seen, current))
    return seen


def test_run_readonly_bounds_cumulative_result_size(monkeypatch):
    _stub_session(monkeypatch, [{"v": "x" * (tables.MAX_RESULT_BYTES + 1)}])
    with pytest.raises(ResultTooLarge, match="fewer properties"):
        run_readonly(Settings(_env_file=None), "RETURN 1 AS v", {})


def test_run_readonly_passes_small_results_through(monkeypatch):
    _stub_session(monkeypatch, [{"v": 1}, {"v": 2}])
    out = run_readonly(Settings(_env_file=None), "RETURN 1 AS v", {})
    assert out == {"columns": ["v"], "data": [{"row": [1]}, {"row": [2]}], "truncated": False}


# --- $snap: every reader pins to the resolved pointer ------------------------------


def test_run_readonly_binds_the_resolved_pointer_as_snap(monkeypatch):
    seen = _stub_session(monkeypatch, [{"v": 1}], current=4242)
    run_readonly(Settings(_env_file=None), "RETURN $snap AS v", {"q": "x"})
    assert seen["kwargs"] == {"parameters": {"q": "x", "snap": 4242}}
    # resolved exactly once for the call, not once per row or per column
    assert seen["pointer_calls"] == 1


def test_run_readonly_falls_back_to_the_live_sentinel_with_no_pointer(monkeypatch):
    seen = _stub_session(monkeypatch, [{"v": 1}], current=None)
    run_readonly(Settings(_env_file=None), "RETURN $snap AS v", {})
    assert seen["kwargs"] == {"parameters": {"snap": "live"}}


def test_run_readonly_keeps_a_caller_supplied_snap_and_never_resolves_the_pointer(monkeypatch):
    seen = _stub_session(monkeypatch, [{"v": 1}], current=4242)
    run_readonly(Settings(_env_file=None), "RETURN $snap AS v", {"snap": 999})
    assert seen["kwargs"] == {"parameters": {"snap": 999}}
    assert seen.get("pointer_calls", 0) == 0


# --- binding cases the MCP tools rely on: cypher, run_query and resolve_context
# all read through run_readonly -------------------------------------------------


def test_run_readonly_binds_caller_params_beside_the_snap_and_leaves_them_unchanged(monkeypatch):
    seen = _stub_session(monkeypatch, [{"n": 1}])
    params = {"ip": "10.0.0.1"}
    out = run_readonly(Settings(_env_file=None), "MATCH (n) RETURN n", params, trusted=True)
    assert out["data"] == [{"row": [1]}]
    assert seen["kwargs"] == {"parameters": {"ip": "10.0.0.1", "snap": "live"}}
    assert params == {"ip": "10.0.0.1"}


def test_run_readonly_resolves_the_pointer_once_for_every_row(monkeypatch):
    seen = _stub_session(monkeypatch, [{"n": 1}, {"n": 2}], current=4242)
    out = run_readonly(Settings(_env_file=None), "MATCH (n) RETURN n", {})
    assert out["data"] == [{"row": [1]}, {"row": [2]}]
    assert seen["kwargs"] == {"parameters": {"snap": 4242}}
    assert seen["pointer_calls"] == 1


def test_run_readonly_keeps_a_caller_snap_on_the_trusted_catalog_path(monkeypatch):
    """MCP run_query passes caller params through, `snap` included."""
    seen = _stub_session(monkeypatch, [{"n": 1}], current=4242)
    run_readonly(Settings(_env_file=None), "MATCH (n) RETURN n", {"snap": 999, "q": "x"}, trusted=True)
    assert seen["kwargs"] == {"parameters": {"snap": 999, "q": "x"}}
    assert seen.get("pointer_calls", 0) == 0


def test_run_readonly_opens_its_session_in_read_mode(monkeypatch):
    opened: list[dict] = []
    seen: dict = {}

    def session(settings, **kwargs):
        opened.append(kwargs)
        return _Session([{"n": 1}], seen)

    monkeypatch.setattr(tables.dbmod, "session", session)
    run_readonly(Settings(_env_file=None), "MATCH (n) RETURN n", {})
    assert opened == [{"access_mode": "READ"}]


# --- graph payload for the node-link view ---------------------------------------


def _graph_fixture():
    from neo4j.graph import Graph, Node

    g = Graph()
    a = Node(g, "4:x:1", 1, ["Device", "Phys"], {"hostname": "core1"})
    b = Node(g, "4:x:2", 2, ["Iface"], {"name": "eth0"})
    rel = g.relationship_type("CABLED")(g, "4:x:9", 9, {"kind": "phys"})
    rel._start_node, rel._end_node = a, b
    return a, b, rel


def test_run_readonly_omits_the_graph_unless_asked(monkeypatch):
    *_, rel = _graph_fixture()
    _stub_session(monkeypatch, [{"r": rel}])
    out = run_readonly(Settings(_env_file=None), "MATCH ()-[r]->() RETURN r", {})
    assert "graph" not in out


def test_run_readonly_returns_nodes_and_edges_when_asked(monkeypatch):
    *_, rel = _graph_fixture()
    _stub_session(monkeypatch, [{"r": rel}])
    out = run_readonly(Settings(_env_file=None), "MATCH ()-[r]->() RETURN r", {}, graph=True)

    nodes = {n["id"]: n for n in out["graph"]["nodes"]}
    assert set(nodes) == {"4:x:1", "4:x:2"}
    assert nodes["4:x:1"]["labels"] == ["Device", "Phys"]
    assert nodes["4:x:1"]["properties"] == {"hostname": "core1"}
    assert out["graph"]["relationships"] == [
        {"id": "4:x:9", "type": "CABLED", "start": "4:x:1", "end": "4:x:2", "properties": {"kind": "phys"}}
    ]
    assert out["graph"]["truncated"] is False
    # the table is unchanged by asking for the graph
    assert out["columns"] == ["r"]


def test_graph_deduplicates_entities_across_rows(monkeypatch):
    """The same device on twenty rows is one node in the view, not twenty."""
    a, b, _rel = _graph_fixture()
    _stub_session(monkeypatch, [{"a": a, "b": b}] * 20)
    out = run_readonly(Settings(_env_file=None), "MATCH (a),(b) RETURN a,b", {}, graph=True)
    assert len(out["graph"]["nodes"]) == 2
    assert out["graph"]["relationships"] == []


def test_graph_collects_through_paths_and_lists(monkeypatch):
    from neo4j.graph import Path

    a, b, rel = _graph_fixture()
    _stub_session(monkeypatch, [{"p": Path(a, rel), "extras": [a, [b]]}])
    out = run_readonly(Settings(_env_file=None), "MATCH p=()-[]->() RETURN p", {}, graph=True)
    assert len(out["graph"]["nodes"]) == 2
    assert len(out["graph"]["relationships"]) == 1


def test_graph_caps_entities_and_says_so(monkeypatch):
    from neo4j.graph import Graph, Node

    g = Graph()
    rows = [
        {"n": Node(g, f"4:x:{i}", i, ["Device"], {"hostname": f"h{i}"})}
        for i in range(tables.MAX_GRAPH_NODES + 25)
    ]
    _stub_session(monkeypatch, rows)
    out = run_readonly(Settings(_env_file=None), "MATCH (n) RETURN n", {}, graph=True)
    assert len(out["graph"]["nodes"]) == tables.MAX_GRAPH_NODES
    assert out["graph"]["truncated"] is True


def test_graph_never_emits_an_edge_into_a_dropped_node(monkeypatch):
    from neo4j.graph import Graph, Node

    g = Graph()
    monkeypatch.setattr(tables, "MAX_GRAPH_NODES", 1)
    a = Node(g, "4:x:1", 1, ["Device"], {})
    b = Node(g, "4:x:2", 2, ["Device"], {})
    rel = g.relationship_type("CABLED")(g, "4:x:9", 9, {})
    rel._start_node, rel._end_node = a, b
    _stub_session(monkeypatch, [{"r": rel}])
    out = run_readonly(Settings(_env_file=None), "MATCH ()-[r]->() RETURN r", {}, graph=True)

    assert out["graph"]["relationships"] == []
    assert len(out["graph"]["nodes"]) == 1
    assert out["graph"]["truncated"] is True


def test_run_readonly_never_splats_params_into_driver_kwargs(monkeypatch):
    params = {"parameters": {"x": 1}, "query": 9}
    seen = _stub_session(monkeypatch, [])
    run_readonly(Settings(_env_file=None), "RETURN $query", params)
    assert seen["args"] == ()
    assert seen["kwargs"] == {"parameters": {**params, "snap": "live"}}


def test_hidden_columns_feed_the_graph_and_never_reach_the_table(monkeypatch):
    a, b, rel = _graph_fixture()
    _stub_session(monkeypatch, [{"hostname": "core1", "_a": a, "_b": b, "_rel": rel}])
    out = run_readonly(Settings(_env_file=None), "q", {}, graph=True)

    assert out["columns"] == ["hostname"]
    assert out["data"] == [{"row": ["core1"], "nodes": ["4:x:1", "4:x:2"]}]
    assert {n["id"] for n in out["graph"]["nodes"]} == {"4:x:1", "4:x:2"}
    assert len(out["graph"]["relationships"]) == 1


def test_graph_payload_bytes_count_toward_the_result_budget(monkeypatch):
    from neo4j.graph import Graph, Node

    g = Graph()
    huge = Node(g, "4:x:1", 1, ["Device"], {"blob": "x" * (tables.MAX_RESULT_BYTES + 1)})
    _stub_session(monkeypatch, [{"hostname": "core1", "_n": huge}])
    with pytest.raises(ResultTooLarge, match="fewer properties"):
        run_readonly(Settings(_env_file=None), "q", {}, graph=True)


def test_the_same_row_passes_when_no_graph_is_requested(monkeypatch):
    """Without graph=True nothing carries the hidden node to the client, so there
    is nothing for the budget to count."""
    from neo4j.graph import Graph, Node

    g = Graph()
    huge = Node(g, "4:x:1", 1, ["Device"], {"blob": "x" * (tables.MAX_RESULT_BYTES + 1)})
    _stub_session(monkeypatch, [{"hostname": "core1", "_n": huge}])
    out = run_readonly(Settings(_env_file=None), "q", {})
    assert out["columns"] == ["hostname"]
    assert out["data"] == [{"row": ["core1"]}]


# --- row node index: the payload nodes each row touched ----------------------------


def test_a_row_lists_the_node_of_its_hidden_column(monkeypatch):
    """The catalog's scalar table names its entities only through `_` columns,
    so those are the nodes a row selects."""
    a, b, _rel = _graph_fixture()
    _stub_session(monkeypatch, [{"hostname": "core1", "_d": a}, {"hostname": "eth0", "_d": b}])
    out = run_readonly(Settings(_env_file=None), "q", {}, graph=True)
    assert out["data"] == [
        {"row": ["core1"], "nodes": ["4:x:1"]},
        {"row": ["eth0"], "nodes": ["4:x:2"]},
    ]


def test_a_path_lists_its_nodes_in_path_order_once(monkeypatch):
    """Walked from b back over the a->b edge and forward again, the path is
    b, a, b: the row lists b then a, and b once."""
    from neo4j.graph import Path

    a, b, rel = _graph_fixture()
    _stub_session(monkeypatch, [{"p": Path(b, rel, rel), "also": a}])
    out = run_readonly(Settings(_env_file=None), "q", {}, graph=True)
    assert out["data"][0]["nodes"] == ["4:x:2", "4:x:1"]


def test_a_node_collected_by_an_earlier_row_is_listed(monkeypatch):
    """The payload holds a node once; every row that reaches it lists it, through
    a relationship's ends too."""
    *_, rel = _graph_fixture()
    _stub_session(monkeypatch, [{"r": rel}, {"r": rel}])
    out = run_readonly(Settings(_env_file=None), "q", {}, graph=True)
    assert [row["nodes"] for row in out["data"]] == [["4:x:1", "4:x:2"], ["4:x:1", "4:x:2"]]


def test_a_node_over_the_cap_is_not_listed(monkeypatch):
    a, b, _rel = _graph_fixture()
    monkeypatch.setattr(tables, "MAX_GRAPH_NODES", 1)
    _stub_session(monkeypatch, [{"n": a}, {"n": b, "m": a}])
    out = run_readonly(Settings(_env_file=None), "q", {}, graph=True)
    assert [row["nodes"] for row in out["data"]] == [["4:x:1"], ["4:x:1"]]
    assert out["graph"]["truncated"] is True


def test_the_ends_of_an_edge_over_its_cap_are_listed(monkeypatch):
    a, b, rel = _graph_fixture()
    monkeypatch.setattr(tables, "MAX_GRAPH_RELS", 0)
    _stub_session(monkeypatch, [{"a": a, "b": b}, {"r": rel}])
    out = run_readonly(Settings(_env_file=None), "q", {}, graph=True)
    assert out["data"][1]["nodes"] == ["4:x:1", "4:x:2"]
    assert out["graph"]["relationships"] == []
    assert out["graph"]["truncated"] is True


def test_rows_carry_no_node_index_without_the_graph(monkeypatch):
    a, *_ = _graph_fixture()
    _stub_session(monkeypatch, [{"hostname": "core1", "_d": a}])
    out = run_readonly(Settings(_env_file=None), "q", {})
    assert out["data"] == [{"row": ["core1"]}]


def test_the_node_index_bytes_count_toward_the_result_budget(monkeypatch):
    """The budget that fits the row and the graph payload exactly is one byte
    short once the row's id list ships too."""
    a, *_ = _graph_fixture()
    rows = [{"hostname": "core1", "_d": a}]
    _stub_session(monkeypatch, rows)
    out = run_readonly(Settings(_env_file=None), "q", {}, graph=True)
    row_bytes = len(json.dumps({"hostname": "core1"}))
    graph_bytes = len(json.dumps(out["graph"]["nodes"][0]))
    ids_bytes = len(json.dumps(["4:x:1"]))

    monkeypatch.setattr(tables, "MAX_RESULT_BYTES", row_bytes + graph_bytes + ids_bytes)
    run_readonly(Settings(_env_file=None), "q", {}, graph=True)
    monkeypatch.setattr(tables, "MAX_RESULT_BYTES", row_bytes + graph_bytes + ids_bytes - 1)
    with pytest.raises(ResultTooLarge, match="fewer properties"):
        run_readonly(Settings(_env_file=None), "q", {}, graph=True)


def test_rows_to_table_attaches_a_node_list_to_each_kept_row():
    count = MAX_ROWS + 2
    out = rows_to_table(["n"], [{"n": i} for i in range(count)], nodes=[[f"4:x:{i}"] for i in range(count)])
    assert len(out["data"]) == MAX_ROWS
    assert out["data"][-1] == {"row": [MAX_ROWS - 1], "nodes": [f"4:x:{MAX_ROWS - 1}"]}


# --- check_readonly: unregistered label / relationship-type identifiers --------


def test_check_readonly_rejects_an_unregistered_label():
    with pytest.raises(QueryRejected, match="unknown identifier"):
        check_readonly("MATCH (n:Frobnicate) RETURN n")


def test_check_readonly_rejects_an_unregistered_relationship_type():
    with pytest.raises(QueryRejected, match="unknown identifier"):
        check_readonly("MATCH (d:Device)-[:FROBS_UP]->(s:Site) RETURN d, s")


def test_check_readonly_passes_registered_labels_and_relationship_types():
    check_readonly("MATCH (d:Device)-[:LOCATED_IN]->(s:Site) MATCH (d)-[:HAS_PORT]->(p:Port) RETURN d, s, p")


def test_check_readonly_passes_a_reversed_relationship_direction():
    check_readonly("MATCH (s:Site)<-[:LOCATED_IN]-(d:Device) RETURN d, s")


def test_check_readonly_ignores_a_colon_inside_a_string_literal():
    """A hostname or routing-domain name containing a colon must not be read as
    a label reference."""
    check_readonly("MATCH (n:Device) WHERE n.hostname = 'switch:core1' RETURN n")


# --- check_pinned: the pinning rule on model-authored Cypher --------------------


@pytest.mark.parametrize(
    "query",
    [
        "MATCH (d:Device) WHERE coalesce(d.collection_ts, $snap) = $snap RETURN d",
        "MATCH (d:Device {collection_ts: $snap}) RETURN d",
        "MATCH (d:Device) WHERE d.collection_ts = $`snap` RETURN d",
    ],
)
def test_check_pinned_passes_a_query_that_references_snap(query):
    assert check_pinned(query) is None


@pytest.mark.parametrize(
    "query",
    [
        "MATCH (d:Device) RETURN d",
        # a reference inside a comment or a string literal binds nothing
        "MATCH (d:Device) // coalesce(d.collection_ts, $snap) = $snap\nRETURN d",
        "MATCH (d:Device) /* $snap */ RETURN d",
        "MATCH (d:Device) RETURN '$snap' AS s",
        # a longer parameter name is a different parameter
        "MATCH (d:Device) WHERE d.collection_ts = $snapshot RETURN d",
    ],
)
def test_check_pinned_refuses_a_query_that_never_references_snap(query):
    with pytest.raises(QueryRejected) as excinfo:
        check_pinned(query)
    assert "x.collection_ts = $snap" in str(excinfo.value)
    assert "coalesce(x.collection_ts" not in str(excinfo.value)


def test_check_pinned_in_warn_mode_returns_the_guidance_and_logs(caplog):
    with caplog.at_level("WARNING", logger="hst.app.tables"):
        assert check_pinned("MATCH (d:Device) RETURN d", "warn") == UNPINNED_QUERY
    assert "reads every retained run" in caplog.text


# --- check_readonly: refusals the model can act on ----------------------------


def test_a_url_literal_refusal_names_the_parameter_form():
    """A URL in a string literal is refused, and the refusal states the two forms
    that match the same value: a parameter, or a part of the value."""
    with pytest.raises(QueryRejected) as refused:
        check_readonly("MATCH (n) WHERE n.url STARTS WITH 'https://portal' RETURN n")
    assert "$url" in str(refused.value)
    assert "CONTAINS 'portal.example.com'" in str(refused.value)
    # and both forms it names pass the guard
    check_readonly("MATCH (n) WHERE n.url = $url RETURN n")
    check_readonly("MATCH (n) WHERE n.url CONTAINS 'portal.example.com' RETURN n")


def test_an_unknown_label_is_refused_with_the_nearest_registered_names():
    with pytest.raises(QueryRejected, match=r"unknown identifier: Devcie \(did you mean Device"):
        check_readonly("MATCH (d:Devcie) RETURN d")
    with pytest.raises(QueryRejected, match=r"CONECTED_TO \(did you mean CONNECTED_TO"):
        check_readonly("MATCH (a:Port)-[:CONECTED_TO]->(b:Port) RETURN a")


def test_a_guessed_domain_label_is_told_where_the_names_are():
    for label in ("Fqdn", "Domain", "Url"):
        with pytest.raises(QueryRejected) as refused:
            check_readonly(f"MATCH (d:{label}) RETURN d")
        assert "ZpaAppSegment.domains" in str(refused.value)
        assert "DnsRecord.fqdn" in str(refused.value)
    # a misspelled label with no name in it gets no such hint
    with pytest.raises(QueryRejected) as refused:
        check_readonly("MATCH (d:Frobnicate) RETURN d")
    assert "ZpaAppSegment" not in str(refused.value)


def test_check_readonly_reads_the_keys_of_a_map_literal_as_keys_not_labels():
    check_readonly(
        "MATCH (fr:FwRule {uid: 'vyos:core1:fw:LAN-WAN:10'}) WHERE coalesce(fr.collection_ts, $snap) = $snap "
        "OPTIONAL MATCH (fr)-[r]-(x) WHERE coalesce(x.collection_ts, $snap) = $snap "
        "RETURN properties(fr) AS rule, "
        "collect({rel: type(r), labels: labels(x), uid: x.uid, name: x.name}) AS links"
    )


def test_check_readonly_passes_a_property_map_with_a_variable_value_and_a_map_projection():
    check_readonly("WITH 'core1' AS h MATCH (n:Device {hostname: h}) RETURN n {.hostname, site: n.site_code}")


def test_check_readonly_rejects_an_unregistered_label_in_a_node_with_a_property_map():
    with pytest.raises(QueryRejected, match="unknown identifier: Frobnicate"):
        check_readonly("MATCH (n:Frobnicate {uid: 'x'}) RETURN {uid: n.uid}")


def test_check_readonly_reads_the_labels_inside_an_existential_or_count_block():
    with pytest.raises(QueryRejected, match="unknown identifier: Frobnicate"):
        check_readonly("MATCH (d:Device) WHERE EXISTS { MATCH (d)-[:LOCATED_IN]->(:Frobnicate) } RETURN d")
    with pytest.raises(QueryRejected, match="unknown identifier: Frobnicate"):
        check_readonly("MATCH (d:Device) RETURN d, COUNT { (d)-[:LOCATED_IN]->(:Frobnicate) } AS n")
    with pytest.raises(QueryRejected, match="unknown identifier: Frobnicate"):
        check_readonly("CALL { MATCH (n:Frobnicate) RETURN n } RETURN n")
