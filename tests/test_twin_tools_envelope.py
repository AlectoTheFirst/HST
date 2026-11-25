"""The catalogue envelope: registration, cursors, the snapshot selector, page
assembly, union inputs, and the snapshot tools that exercise them."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from tests.twin_tools_fakes import FakeGraph, call, context, install, settings

from hst.app.ai import mcp as ai_mcp
from hst.app.ai.registry import Principal, ToolError
from hst.twin_tools import catalogue_registry, selectors
from hst.twin_tools.envelope import PAGE_BUDGET_BYTES, Pager, ToolErrorPayload

CATALOGUE = [
    "snapshot_list",
    "snapshot_resolve",
    "snapshot_diff",
    "inventory_search",
    "inventory_get",
    "inventory_list",
    "inventory_resolve",
    "routing_routes",
    "routing_bgp",
    "routing_evaluate_policy",
    "routing_predict_routes",
    "policy_evaluate",
    "policy_lookup_nat",
    "lb_lookup_vip",
    "reach_trace",
    "reach_audit_mtu",
    "impact_evaluate_service",
    "impact_assess",
    "change_simulate",
    "change_get_simulation",
    "app_applications",
    "app_find_affected",
    "assessment_read",
    "evidence_get_gaps",
    "ops_list_collection_runs",
    "query_catalog",
    "query_run_named",
    "query_cypher",
]

# The least arguments each catalogue tool runs with.
MINIMAL_ARGS: dict[str, dict] = {
    "snapshot_list": {},
    "snapshot_resolve": {},
    "snapshot_diff": {"base": "3000"},
    "inventory_search": {"q": "core1"},
    "inventory_get": {"kind": "device", "device": "dev:core1"},
    "inventory_list": {"kind": "zones"},
    "inventory_resolve": {"kind": "address", "address": "10.0.0.1"},
    "routing_routes": {"mode": "lookup", "device": "dev:core1", "address": "10.0.0.1"},
    "routing_bgp": {"mode": "sessions"},
    "routing_evaluate_policy": {
        "device": "dev:core1",
        "policy_name": "RM-IN",
        "direction": "import",
        "route": {"prefix": "10.0.0.0/8"},
    },
    "routing_predict_routes": {"scope": "dev:core1"},
    "policy_evaluate": {"mode": "explain_rule", "rulebase": "fw:rb", "rule": "fw:rb/r1"},
    "policy_lookup_nat": {"address": "10.0.0.1"},
    "lb_lookup_vip": {"address": "10.0.0.1", "direction": "vip_to_members"},
    "reach_trace": {"mode": "path", "flow": {"src": "10.0.0.1", "dst": "10.0.0.2"}},
    "reach_audit_mtu": {},
    "impact_evaluate_service": {"form": "requirement", "requirement": "sreq:app"},
    "impact_assess": {"subject": "device", "device": "dev:core1"},
    "change_simulate": {"intents": [{"kind": "fw_rule.add"}]},
    "change_get_simulation": {"session_id": "s1", "run_id": "r1"},
    "app_applications": {"mode": "list"},
    "app_find_affected": {"inventory_uids": ["dev:core1"]},
    "assessment_read": {"mode": "list"},
    "evidence_get_gaps": {"subject": {"kind": "device", "id": "dev:core1"}},
    "ops_list_collection_runs": {},
    "query_catalog": {"mode": "schema"},
    "query_run_named": {"key": "devices"},
    "query_cypher": {"query": "MATCH (d:Device) WHERE coalesce(d.collection_ts, $snap) = $snap RETURN d.uid"},
}


def _mcp_settings(monkeypatch, **overrides):
    monkeypatch.setattr(ai_mcp, "Settings", lambda: settings(**overrides))


# --- criterion 1: permission, annotations and the envelope output schema -------------------


def test_the_catalogue_lists_its_tools_in_catalogue_order():
    specs = catalogue_registry().specs()

    assert [spec.name for spec in specs] == CATALOGUE
    assert {spec.name: spec.permission for spec in specs if spec.permission != "graph.read"} == {
        "ops_list_collection_runs": "runs.manage",
        "query_cypher": "cypher.run",
    }
    assert all(
        spec.kind == "read" and spec.surfaces == frozenset({"mcp", "drawer", "changesim", "assessment_qa"})
        for spec in specs
    )


async def test_every_catalogue_tool_publishes_annotations_and_an_envelope_output_schema():
    pytest.importorskip("mcp")
    from hst.mcp_server import build_server

    # with the app store, the local principal is offered the runs.manage tool too
    tools = {t.name: t for t in await build_server(Principal.local(store=True)).list_tools()}

    assert set(tools) == set(CATALOGUE)
    for name in CATALOGUE:
        tool = tools[name]
        assert tool.annotations is not None, name
        assert tool.annotations.read_only_hint is True, name
        assert tool.annotations.open_world_hint is False, name
        schema = tool.output_schema
        assert schema is not None, name
        assert set(schema["required"]) >= {"snapshot", "provenance", "evidence", "page", "result"}, name
        assert tool.description, name


def test_a_tool_error_payload_has_the_published_shape():
    error = ToolError("ambiguous", "two devices match", field="device", candidates=[{"uid": "dev:a"}])

    assert ToolErrorPayload.model_validate(error.payload()).error.code == "ambiguous"


# --- criterion 3: an unknown snapshot -------------------------------------------------------


@pytest.mark.parametrize("name", CATALOGUE)
async def test_an_unknown_snapshot_is_snapshot_not_found_with_is_error(monkeypatch, name):
    pytest.importorskip("mcp")
    from hst.mcp_server import build_server

    _mcp_settings(monkeypatch)
    graph = install(monkeypatch, FakeGraph())

    res = await build_server(Principal.local(store=True)).call_tool(
        name, {**MINIMAL_ARGS[name], "snapshot": "2500"}
    )

    assert res.is_error is True
    assert res.structured_content["error"]["code"] == "snapshot_not_found"
    assert res.structured_content["error"]["field"] == "snapshot"
    assert "unknown run 2500" in res.structured_content["error"]["message"]
    # the existence check is the only read
    assert graph.calls == []


@pytest.mark.parametrize("value", ["yesterday", "-1", "99999999999999999999"])
async def test_a_snapshot_outside_the_selector_pattern_is_refused_before_the_tool_runs(monkeypatch, value):
    pytest.importorskip("mcp")
    from mcp.server.mcpserver.exceptions import ToolError as McpToolError

    from hst.mcp_server import build_server

    _mcp_settings(monkeypatch)
    graph = install(monkeypatch, FakeGraph())

    with pytest.raises(McpToolError, match="should match pattern"):
        await build_server().call_tool("snapshot_list", {"snapshot": value})

    assert graph.session_kwargs == []


async def test_a_run_id_past_the_64_bit_range_is_invalid_argument(monkeypatch):
    pytest.importorskip("mcp")
    from hst.mcp_server import build_server

    _mcp_settings(monkeypatch)
    graph = install(monkeypatch, FakeGraph())

    res = await build_server().call_tool("snapshot_list", {"snapshot": "9999999999999999999"})

    assert res.is_error is True
    assert res.structured_content["error"]["code"] == "invalid_argument"
    assert res.structured_content["error"]["field"] == "snapshot"
    assert graph.calls == []


def test_a_run_id_sent_as_a_number_selects_that_run(monkeypatch):
    graph = install(monkeypatch, FakeGraph())

    failed, envelope = call("snapshot_list", {"snapshot": 3000})

    assert not failed
    assert envelope["snapshot"]["id"] == "3000"
    assert envelope["snapshot"]["selector"] == "3000"
    assert graph.reads("MATCH (c:CycleRun)")


def test_latest_resolves_the_pointer_once(monkeypatch):
    install(monkeypatch, FakeGraph(current=4000))

    failed, envelope = call("query_catalog", {"mode": "schema"})

    assert not failed
    assert envelope["snapshot"] == {
        "id": "4000",
        "collection_ts": 4000,
        "selector": "latest",
        "manifest_sha256": None,
        "approximate": True,
        "run": None,
    }


def test_the_envelope_carries_provenance(monkeypatch):
    install(monkeypatch, FakeGraph())

    _, first = call("query_catalog", {"mode": "list", "group": "inventory"})
    _, second = call("query_catalog", {"mode": "list", "group": "inventory", "snapshot": "3000"})
    _, other = call("query_catalog", {"mode": "list", "group": "routing"})

    provenance = first["provenance"]
    assert provenance["tool"] == "query_catalog"
    assert provenance["tool_version"] == catalogue_registry().get("query_catalog").version
    assert provenance["engine_function"] == "hst.queries.catalog"
    assert datetime.fromisoformat(provenance["computed_at"]).tzinfo is not None
    # the digest leaves out the run and the paging arguments
    assert provenance["args_sha256"] == second["provenance"]["args_sha256"]
    assert provenance["args_sha256"] != other["provenance"]["args_sha256"]


def test_an_envelope_carries_the_catalogue_version_of_its_tool(monkeypatch):
    from hst.core import diff

    install(monkeypatch, FakeGraph(current=4000))
    monkeypatch.setattr(diff, "request_diff", _diff)

    _, envelope = call("snapshot_diff", {"base": "3000"})

    assert envelope["provenance"]["tool"] == "snapshot_diff"
    assert envelope["provenance"]["tool_version"] == catalogue_registry().get("snapshot_diff").version == 3


# --- criterion 2: cursors -------------------------------------------------------------------


def _runs(count: int) -> list[dict]:
    return [
        {
            "id": 5000 - i,
            "ts_ms": 5000 - i,
            "created": None,
            "kind": "full",
            "parent": None,
            "degraded": False,
        }
        for i in range(count)
    ]


def _list_cycles(params):
    rows = _runs(30)
    return rows[params["offset"] : params["offset"] + params["limit"]]


def test_snapshot_list_pages_with_a_cursor(monkeypatch):
    install(monkeypatch, FakeGraph([("MATCH (c:CycleRun)", _list_cycles)], current=5000, retained=(5000,)))

    _, first = call("snapshot_list", {"limit": 10})
    _, second = call("snapshot_list", {"limit": 10, "cursor": first["page"]["next_cursor"]})

    assert [r["id"] for r in first["result"]["runs"]] == [str(5000 - i) for i in range(10)]
    assert first["page"]["truncated"] is True
    assert first["result"]["current"] == "5000"
    assert first["result"]["runs"][0]["is_current"] is True
    assert first["result"]["runs"][0]["is_selected"] is True
    assert [r["id"] for r in second["result"]["runs"]] == [str(5000 - i) for i in range(10, 20)]
    assert second["result"]["runs"][0]["is_current"] is False


def test_a_cursor_from_another_tool_run_or_argument_set_is_cursor_mismatch(monkeypatch):
    install(
        monkeypatch,
        FakeGraph([("MATCH (c:CycleRun)", _list_cycles)], current=5000, retained=(4990, 5000)),
    )
    _, first = call("snapshot_list", {"limit": 10})
    cursor = first["page"]["next_cursor"]

    failed, error = call("inventory_search", {"q": "core1", "cursor": cursor})
    assert failed and error["error"]["code"] == "cursor_mismatch"
    failed, error = call("snapshot_list", {"limit": 10, "cursor": cursor, "snapshot": "4990"})
    assert failed and error["error"]["code"] == "cursor_mismatch"
    assert "run 5000" in error["error"]["message"]


def test_a_cursor_for_other_arguments_is_cursor_mismatch(monkeypatch):
    rows = [
        {"uid": f"dev:d{i}", "label": "Device", "name": f"d{i}", "detail": "", "matched": "text"}
        for i in range(60)
    ]
    install(monkeypatch, FakeGraph([("obj_names", rows)]))

    _, first = call("inventory_search", {"q": "core"})
    failed, error = call("inventory_search", {"q": "edge", "cursor": first["page"]["next_cursor"]})

    assert first["page"]["truncated"] is True
    assert failed and error["error"]["code"] == "cursor_mismatch"
    assert error["error"]["field"] == "cursor"


def test_a_cursor_that_does_not_decode_is_invalid_argument():
    with pytest.raises(ToolError) as refused:
        selectors.decode_cursor("not a cursor", "snapshot_list", "4000", "0" * 64)

    assert refused.value.code == "invalid_argument"


def test_a_cursor_names_its_tool_run_digest_and_position():
    cursor = selectors.encode_cursor("snapshot_list", "4000", "a" * 64, 20)

    assert selectors.decode_cursor(cursor, "snapshot_list", "4000", "a" * 64) == 20
    for tool, run, digest in (("inventory_search", "4000", "a" * 64), ("snapshot_list", "3000", "a" * 64)):
        with pytest.raises(ToolError) as refused:
            selectors.decode_cursor(cursor, tool, run, digest)
        assert refused.value.code == "cursor_mismatch"
    with pytest.raises(ToolError) as refused:
        selectors.decode_cursor(cursor, "snapshot_list", "4000", "b" * 64)
    assert refused.value.code == "cursor_mismatch"


# --- criterion 4: the 256 KiB page ----------------------------------------------------------


def test_a_page_stops_before_256_kib_and_sets_truncated_and_next_cursor():
    pager = Pager(tool="inventory_search", snapshot_id="4000", digest="c" * 64, offset=0, limit=200)
    items = [{"uid": f"dev:{i}", "blob": "x" * 2000} for i in range(200)]

    page, out = pager.take(items, total=len(items))

    size = sum(len(json.dumps(item)) + 1 for item in page)
    assert size <= PAGE_BUDGET_BYTES
    assert size + len(json.dumps(items[len(page)])) + 1 > PAGE_BUDGET_BYTES
    assert 0 < len(page) < 200
    assert out.truncated is True
    assert selectors.decode_cursor(out.next_cursor, "inventory_search", "4000", "c" * 64) == len(page)
    assert out.total == 200


def test_a_page_within_limit_and_budget_is_not_truncated():
    pager = Pager(tool="snapshot_list", snapshot_id=None, digest="d" * 64, offset=40, limit=50)

    page, out = pager.take([{"id": i} for i in range(5)])

    assert len(page) == 5
    assert out.truncated is False and out.next_cursor is None


def test_a_page_holds_at_least_one_item_however_large():
    pager = Pager(tool="snapshot_list", snapshot_id=None, digest="d" * 64, offset=0, limit=50)

    page, out = pager.take([{"blob": "x" * (PAGE_BUDGET_BYTES + 1)}, {"blob": "y"}])

    assert len(page) == 1
    assert out.truncated is True


def test_a_tool_page_that_would_exceed_256_kib_is_truncated(monkeypatch):
    rows = [
        {"uid": f"dev:d{i}", "label": "Device", "name": "n", "detail": "x" * 4000, "matched": "text"}
        for i in range(150)
    ]
    install(monkeypatch, FakeGraph([("obj_names", rows)]))

    failed, envelope = call("inventory_search", {"q": "core", "limit": 200})

    assert not failed
    page = envelope["page"]
    assert page["truncated"] is True and page["next_cursor"]
    assert len(envelope["result"]["items"]) < 150
    assert len(json.dumps(envelope["result"]["items"])) <= PAGE_BUDGET_BYTES


# --- criterion 6: each mode publishes its own required fields -------------------------------


def _mode_required(schema: dict, discriminator: str) -> dict[str, list[str]]:
    out = {}
    for branch in schema["oneOf"]:
        variant = schema["$defs"][branch["$ref"].rsplit("/", 1)[-1]]
        out[variant["properties"][discriminator]["const"]] = sorted(variant["required"])
    return out


async def test_each_mode_of_a_union_tool_publishes_its_own_required_fields():
    pytest.importorskip("mcp")
    from hst.mcp_server import build_server

    tools = {t.name: t.input_schema for t in await build_server().list_tools()}

    assert _mode_required(tools["inventory_get"], "kind") == {
        "device": ["device", "kind"],
        "site": ["kind"],
    }
    assert _mode_required(tools["inventory_list"], "kind") == {
        "interfaces": ["device", "kind"],
        "zones": ["kind"],
    }
    assert _mode_required(tools["inventory_resolve"], "kind") == {
        "context": ["kind", "name"],
        "address": ["address", "kind"],
    }
    assert _mode_required(tools["query_catalog"], "mode") == {"schema": ["mode"], "list": ["mode"]}
    for name, discriminator in (
        ("inventory_get", "kind"),
        ("inventory_list", "kind"),
        ("inventory_resolve", "kind"),
        ("query_catalog", "mode"),
    ):
        schema = tools[name]
        assert schema["type"] == "object"
        assert schema["required"] == [discriminator]
        assert "snapshot" in schema["properties"]


async def test_a_mode_called_without_its_required_field_is_invalid_argument(monkeypatch):
    pytest.importorskip("mcp")
    from hst.mcp_server import build_server

    _mcp_settings(monkeypatch)
    graph = install(monkeypatch, FakeGraph())

    res = await build_server().call_tool("inventory_get", {"kind": "device"})

    assert res.is_error is True
    assert res.structured_content["error"]["code"] == "invalid_argument"
    assert "device" in res.structured_content["error"]["message"]
    assert graph.calls == []


async def test_a_malformed_optional_field_of_a_union_tool_is_invalid_argument(monkeypatch):
    pytest.importorskip("mcp")
    from hst.mcp_server import build_server

    _mcp_settings(monkeypatch)
    graph = install(monkeypatch, FakeGraph())

    res = await build_server().call_tool("inventory_get", {"kind": "site", "snapshot": "last week"})

    assert res.is_error is True
    assert res.structured_content["error"]["code"] == "invalid_argument"
    assert res.structured_content["error"]["field"] == "snapshot"
    assert graph.calls == []


async def test_a_mode_takes_only_its_own_fields(monkeypatch):
    pytest.importorskip("mcp")
    from hst.mcp_server import build_server

    _mcp_settings(monkeypatch)
    install(monkeypatch, FakeGraph())

    res = await build_server().call_tool("inventory_get", {"kind": "site", "device": "dev:a"})

    assert res.is_error is True
    assert res.structured_content["error"]["code"] == "invalid_argument"


async def test_an_mcp_success_returns_the_envelope_as_structured_content(monkeypatch):
    pytest.importorskip("mcp")
    from hst.mcp_server import build_server

    _mcp_settings(monkeypatch)
    install(monkeypatch, FakeGraph())

    res = await build_server().call_tool("query_catalog", {"mode": "schema"})

    assert res.is_error is False
    assert res.structured_content["provenance"]["tool"] == "query_catalog"
    assert res.structured_content["result"]["mode"] == "schema"
    # the text is framed as device-collected data; inside the frame it is the envelope
    from hst.app.agent.tools import unframe

    assert res.content[0].text.startswith('<tool_result tool="query_catalog"')
    assert json.loads(unframe(res.content[0].text)) == res.structured_content


def test_a_principal_without_the_permission_is_denied(monkeypatch):
    install(monkeypatch, FakeGraph())
    reader = Principal(user_id=7, role="viewer", permissions=frozenset({"graph.read"}), origin="mcp")

    failed, error = call("query_cypher", MINIMAL_ARGS["query_cypher"], context(reader))

    assert failed and error["error"]["code"] == "permission_denied"


# --- snapshot_resolve and snapshot_diff -----------------------------------------------------


def _resolve_at(params):
    runs = [{"cts": 3000, "kind": "full", "created": "2026-09-01T00:00:03Z"}]
    return [r for r in runs if r["cts"] <= params["bound"]]


def test_snapshot_resolve_resolves_an_instant_through_the_route_body(monkeypatch):
    install(monkeypatch, FakeGraph([("c.cts <= $bound", _resolve_at)], current=4000))

    failed, envelope = call("snapshot_resolve", {"at": "1970-01-01T00:00:03.500Z"})

    assert not failed
    assert envelope["snapshot"]["id"] == "3000"
    assert envelope["result"]["snapshot"] == "3000"
    assert envelope["result"]["kind"] == "full"
    assert envelope["result"]["approximate"] is True
    assert envelope["result"]["devices"] == []


def test_snapshot_resolve_before_any_committed_run_is_not_found(monkeypatch):
    install(monkeypatch, FakeGraph([("c.cts <= $bound", _resolve_at)], current=4000))

    failed, error = call("snapshot_resolve", {"at": "1970-01-01T00:00:01Z"})

    assert failed and error["error"]["code"] == "not_found"


def test_snapshot_resolve_with_no_published_run_is_snapshot_not_published(monkeypatch):
    install(monkeypatch, FakeGraph(current=None))

    failed, error = call("snapshot_resolve", {"at": "2026-09-01T00:00:00Z"})

    assert failed and error["error"]["code"] == "snapshot_not_published"


def test_snapshot_resolve_pages_the_devices_of_the_manifest(monkeypatch, tmp_path):
    install(
        monkeypatch, FakeGraph([("coalesce(c.kind, 'full') AS kind", [{"kind": "delta", "created": "t"}])])
    )
    devices = [
        SimpleNamespace(
            source="lab",
            host=f"r{i}",
            outcome="collected",
            effective_run="4000",
            carried=False,
            fetch_ts_ms=4000,
            fetch_started_ms=None,
            fetch_finished_ms=None,
            ingested_ms=None,
            scope=None,
            sections={"arp": SimpleNamespace(status="complete")},
            tables={"rib": SimpleNamespace(status="complete-empty")},
        )
        for i in range(3)
    ]
    record = SimpleNamespace(devices=devices, published=4100)
    from hst.core import snapshot as snapshotmod

    monkeypatch.setattr(snapshotmod.Snapshot, "_read_manifest", lambda self: record)

    failed, envelope = call(
        "snapshot_resolve", {"limit": 2, "include_health": True}, context(manifests_dir=tmp_path)
    )

    assert not failed
    result = envelope["result"]
    assert result["kind"] == "delta" and result["published"] == 4100 and result["approximate"] is False
    assert [d["host"] for d in result["devices"]] == ["r0", "r1"]
    assert result["devices"][0]["sections"] == {"arp": "complete"}
    assert result["devices"][0]["tables"] == {"rib": "complete-empty"}
    assert envelope["page"]["truncated"] is True and envelope["page"]["total"] == 3


def _diff(archive, a, b, *, devices_b=None):
    return {
        "a": a,
        "b": b,
        "counts": {
            "nodes": {"added": 1, "removed": 2, "changed": 0},
            "rels": {"added": 0, "removed": 1, "changed": 0},
        },
        "nodes": {
            "added": [{"uid": "dev:new", "label": "Device", "name": "new"}],
            "removed": [
                {"uid": "dev:gone", "label": "Device", "name": "gone", "status": "removed"},
                {"uid": "dev:quiet", "label": "Device", "name": "quiet", "status": "unknown"},
            ],
            "changed": [],
        },
        "rels": {"added": [], "removed": [{"type": "ON", "start": "if:a", "end": "dev:gone"}], "changed": []},
        "conflicts": {"a": [], "b": [], "counts": {"a": 0, "b": 0}},
        "truncated": False,
    }


def test_snapshot_diff_reports_counts_and_qualified_removals(monkeypatch):
    from hst.core import diff

    install(monkeypatch, FakeGraph(current=4000))
    monkeypatch.setattr(diff, "request_diff", _diff)

    _, counts_only = call("snapshot_diff", {"base": "3000"})
    _, removed = call("snapshot_diff", {"base": "3000", "bucket": "nodes.removed"})
    _, rels = call("snapshot_diff", {"base": "3000", "bucket": "rels.removed"})

    assert counts_only["result"]["counts"]["nodes"]["removed"] == 2
    assert counts_only["result"]["items"] == []
    assert counts_only["evidence"]["result"]["word"] == "recorded in the snapshot"
    items = removed["result"]["items"]
    assert [(i["uid"], i["removal"], i["evidence"]["result"]["answer"]) for i in items] == [
        ("dev:gone", "removed", "false"),
        ("dev:quiet", "unknown", "open"),
    ]
    assert items[0]["evidence"]["result"]["word"] == "removed"
    assert removed["evidence"]["result"]["word"] == "each item states its own result"
    assert rels["result"]["items"][0]["evidence"]["result"]["answer"] == "open"


def test_snapshot_diff_with_an_unknown_base_is_snapshot_not_found(monkeypatch):
    install(monkeypatch, FakeGraph(current=4000, retained=(4000,)))

    failed, error = call("snapshot_diff", {"base": "2000"})

    assert failed
    assert error["error"]["code"] == "snapshot_not_found"
    assert error["error"]["field"] == "base"


def test_snapshot_diff_reports_a_comparison_past_its_timeout_as_retryable(monkeypatch):
    from hst.core import diff

    def slow(archive, a, b, *, devices_b=None):
        raise diff.DiffTimeout("comparing runs 3000 and 4000 took longer than 120 s")

    install(monkeypatch, FakeGraph(current=4000))
    monkeypatch.setattr(diff, "request_diff", slow)

    failed, error = call("snapshot_diff", {"base": "3000"})

    assert failed and error["error"]["code"] == "timeout"
    assert error["error"]["retryable"] is True


def test_snapshot_diff_reports_a_bucket_past_the_detail_cap(monkeypatch):
    from hst.core import diff

    def big(archive, a, b, *, devices_b=None):
        out = _diff(archive, a, b)
        out["counts"]["nodes"]["added"] = 800
        return out

    install(monkeypatch, FakeGraph(current=4000))
    monkeypatch.setattr(diff, "request_diff", big)

    _, envelope = call("snapshot_diff", {"base": "3000", "bucket": "nodes.added"})

    assert envelope["result"]["bucket_count"] == 800
    assert envelope["result"]["bucket_truncated"] is True
    assert any("first 500" in text for text in envelope["evidence"]["unknowns"])


def test_the_computed_at_time_is_utc(monkeypatch):
    install(monkeypatch, FakeGraph())

    _, envelope = call("query_catalog", {"mode": "schema"})

    assert datetime.fromisoformat(envelope["provenance"]["computed_at"]).utcoffset() == timedelta(0)
