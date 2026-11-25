"""The query tools: the catalog, named queries and model-authored Cypher."""

from __future__ import annotations

import hashlib

import pytest
from tests.twin_tools_fakes import FakeGraph, call, context, install

from hst.app.tables import UNPINNED_QUERY
from hst.queries import catalog
from hst.twin_tools.query import SCHEMA_CONVENTIONS, graph_schema

GUARDED = "MATCH (d:Device) WHERE coalesce(d.collection_ts, $snap) = $snap RETURN d.hostname AS n"
# A query without $snap, and one that holds $snap outside a pinning predicate.
UNGUARDED = ["MATCH (d:Device) RETURN d", "MATCH (d:Device) WHERE $snap IS NOT NULL RETURN d"]


# --- query_catalog -------------------------------------------------------------------------


def test_schema_mode_returns_the_graph_model_and_the_conventions(monkeypatch):
    install(monkeypatch, FakeGraph())

    failed, envelope = call("query_catalog", {"mode": "schema"})

    assert not failed
    result = envelope["result"]
    assert result["mode"] == "schema"
    assert result["labels"] == graph_schema()["labels"]
    assert result["conventions"] == list(SCHEMA_CONVENTIONS)
    assert envelope["evidence"]["result"]["word"] == "recorded in the snapshot"


def test_the_conventions_teach_the_snap_guard():
    conventions = " ".join(SCHEMA_CONVENTIONS)

    assert "x.collection_ts = $snap" in conventions

    assert "coalesce(x.collection_ts" not in conventions
    assert "An unguarded MATCH reads every retained run" in conventions
    assert "already pinned" not in conventions


def test_schema_mode_with_a_label_samples_its_property_keys(monkeypatch):
    rows = [{"sampled": 3, "key": "hostname", "nodes": 3}, {"sampled": 3, "key": "serial", "nodes": 1}]
    graph = install(monkeypatch, FakeGraph([("UNWIND keys(n) AS key", rows)]))

    failed, envelope = call("query_catalog", {"mode": "schema", "label": "Device", "snapshot": "3000"})

    assert not failed
    result = envelope["result"]
    assert list(result["labels"]) == ["Device"]
    assert result["properties"] == [{"name": "hostname", "nodes": 3}, {"name": "serial", "nodes": 1}]
    assert result["sampled_nodes"] == 3
    assert graph.reads("UNWIND keys(n) AS key") == [{"snap": 3000}]


def test_schema_mode_refuses_an_unknown_label(monkeypatch):
    graph = install(monkeypatch, FakeGraph())

    failed, error = call("query_catalog", {"mode": "schema", "label": "Device`) DETACH DELETE n //"})

    assert failed and error["error"]["code"] == "invalid_argument"
    assert graph.session_kwargs == []


def test_list_mode_returns_the_named_queries_of_one_group(monkeypatch):
    install(monkeypatch, FakeGraph())

    _, everything = call("query_catalog", {"mode": "list"})
    _, inventory = call("query_catalog", {"mode": "list", "group": "inventory"})

    keys = [item["key"] for item in everything["result"]["items"]]
    assert keys == [entry["key"] for entry in catalog()]
    assert inventory["result"]["items"]
    assert {item["group"] for item in inventory["result"]["items"]} == {"inventory"}
    assert all("cypher" in item for item in inventory["result"]["items"])
    assert not any("fixture_only" in item for item in inventory["result"]["items"])


# --- query_run_named -----------------------------------------------------------------------


def _named_with_params():
    return next(entry for entry in catalog() if entry.get("params"))


def test_a_named_query_binds_its_declared_params_and_the_selected_run(monkeypatch):
    entry = _named_with_params()
    declared = {p["name"]: "x" for p in entry["params"]}
    graph = install(monkeypatch, FakeGraph([(entry["cypher"], [{"n": 1}])]))

    failed, envelope = call(
        "query_run_named", {"key": entry["key"], "params": {**declared, "extra": "y"}, "snapshot": "3000"}
    )

    assert not failed
    assert envelope["result"]["columns"] == ["n"]
    assert envelope["result"]["data"] == [{"row": [1]}]
    assert envelope["provenance"]["queries"] == [{"kind": "catalog", "id": entry["key"]}]
    # only the declared params reach Cypher, and snap is the selected run
    assert graph.reads(entry["cypher"]) == [{**declared, "snap": 3000}]


def test_a_named_query_with_a_missing_param_is_invalid_argument(monkeypatch):
    entry = _named_with_params()
    graph = install(monkeypatch, FakeGraph())

    failed, error = call("query_run_named", {"key": entry["key"]})

    assert failed and error["error"]["code"] == "invalid_argument"
    assert graph.session_kwargs == []


def test_a_named_query_with_a_blank_required_param_is_invalid_argument(monkeypatch):
    entry = _named_with_params()
    required = next(p["name"] for p in entry["params"] if not p.get("optional"))
    graph = install(monkeypatch, FakeGraph())

    failed, error = call("query_run_named", {"key": entry["key"], "params": {required: "  "}})

    assert failed and error["error"]["code"] == "invalid_argument"
    assert graph.session_kwargs == []


def test_an_unknown_named_query_is_not_found(monkeypatch):
    install(monkeypatch, FakeGraph())

    failed, error = call("query_run_named", {"key": "no-such-query"})

    assert failed and error["error"]["code"] == "not_found" and error["error"]["field"] == "key"


# --- query_cypher --------------------------------------------------------------------------


def test_a_guarded_query_runs_on_the_selected_run_and_is_audited(monkeypatch):
    graph = install(monkeypatch, FakeGraph([("RETURN d.hostname AS n", [{"n": "core1"}])]))
    ctx = context()

    failed, envelope = call("query_cypher", {"query": GUARDED, "snapshot": "3000"}, ctx)

    assert not failed
    assert envelope["result"]["data"] == [{"row": ["core1"]}]
    assert envelope["result"]["pinned"] is True
    assert envelope["provenance"]["queries"] == [
        {"kind": "cypher", "id": hashlib.sha256(GUARDED.encode()).hexdigest()}
    ]
    assert graph.reads("RETURN d.hostname AS n") == [{"snap": 3000}]
    ((query, outcome, rows, size),) = [
        (a.query, a.outcome, a.row_count, a.byte_count) for a in ctx.cypher_log
    ]
    assert (query, outcome, rows) == (GUARDED, "ok", 1) and size > 0


def test_params_pass_through_beside_the_bound_run(monkeypatch):
    graph = install(monkeypatch, FakeGraph())

    call("query_cypher", {"query": GUARDED + " LIMIT $n", "params": {"n": 5}})

    assert graph.reads("LIMIT $n") == [{"n": 5, "snap": 4000}]


@pytest.mark.parametrize("query", UNGUARDED)
def test_an_unguarded_query_is_refused_before_any_read_and_audited(monkeypatch, query):
    graph = install(monkeypatch, FakeGraph())
    ctx = context()

    failed, error = call("query_cypher", {"query": query}, ctx)

    assert failed and error["error"]["code"] == "invalid_argument"
    assert error["error"]["message"] == UNPINNED_QUERY
    assert "x.collection_ts = $snap" in error["error"]["message"]
    assert "coalesce(x.collection_ts" not in error["error"]["message"]
    assert graph.session_kwargs == []
    assert [(a.query, a.outcome) for a in ctx.cypher_log] == [(query, "rejected")]


@pytest.mark.parametrize("query", UNGUARDED)
def test_the_warn_setting_runs_an_unguarded_query_with_a_warning(monkeypatch, query):
    install(monkeypatch, FakeGraph([("RETURN d", [{"d": 1}])]))

    failed, envelope = call("query_cypher", {"query": query}, context(hst_ai_cypher_pinning="warn"))

    assert not failed
    assert envelope["result"]["pinned"] is False
    assert envelope["warnings"] == [UNPINNED_QUERY]
    assert envelope["evidence"]["unknowns"] == envelope["warnings"]


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        ({"query": "MATCH (d:Device:Latest) WHERE d.x = $snap RETURN d"}, "invalid_argument"),
        ({"query": GUARDED, "params": {"snap": 1}}, "invalid_argument"),
        ({"query": "SHOW TRANSACTIONS WHERE $snap IS NOT NULL"}, "invalid_argument"),
    ],
)
def test_refused_queries_reach_no_database_read(monkeypatch, arguments, code):
    graph = install(monkeypatch, FakeGraph())
    ctx = context()

    failed, error = call("query_cypher", arguments, ctx)

    assert failed and error["error"]["code"] == code
    assert graph.calls == []
    assert [a.outcome for a in ctx.cypher_log] == ["rejected"]


def test_a_query_over_64_kib_is_limit_exceeded(monkeypatch):
    graph = install(monkeypatch, FakeGraph())
    ctx = context()

    # the cap counts encoded bytes: this text is under 65,536 characters and over 64 KiB
    failed, error = call("query_cypher", {"query": GUARDED + " //" + "é" * 33_000}, ctx)

    assert failed and error["error"]["code"] == "limit_exceeded"
    assert [a.outcome for a in ctx.cypher_log] == ["too_large"]
    assert graph.session_kwargs == []
