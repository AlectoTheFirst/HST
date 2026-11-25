"""The `hst mcp` server: the principals, the published catalogue, the retired tool names
and the call audit."""

import pytest
from tests import twin_tools_fakes as fakes

from hst import mcp_server
from hst.app.ai import mcp as ai_mcp
from hst.app.ai.registry import Principal
from hst.core import Settings

_GUARDED = "MATCH (d:Device) WHERE coalesce(d.collection_ts, $snap) = $snap RETURN d.hostname AS n"

_RETIRED = {
    "saved_assessments": "assessment_read, mode: list, or mode: run",
    "trace_path": "reach_trace, mode: path",
    "mtu_audit": "reach_audit_mtu",
    "schema": "query_catalog, mode: schema",
    "list_queries": "query_catalog, mode: list",
    "run_query": "query_run_named",
    "resolve_context": "inventory_resolve, kind: context",
    "evaluate_service_impact": "impact_evaluate_service, form: requirement or form: request",
    "cypher": "query_cypher",
}


# --- local principal, envelope profile and call audit -------------------------------


def test_the_local_principal_holds_no_write_permission():
    bare, with_store = Principal.local(), Principal.local(store=True)

    assert bare.user_id is None and with_store.user_id is None
    assert bare.origin == with_store.origin == "mcp"
    assert bare.permissions == {"graph.read", "cypher.run"}
    assert with_store.permissions == {"graph.read", "cypher.run", "runs.manage"}


def test_the_local_principal_is_offered_no_write_tool():
    from hst.twin_tools import catalogue_registry, write_registry

    def offered(principal):
        registries = (catalogue_registry(), write_registry())
        return [spec.name for registry in registries for spec in registry.offered(principal, "mcp")]

    bare = offered(Principal.local())
    with_store = offered(Principal.local(store=True))
    writes = {spec.name for spec in write_registry().specs()}

    assert writes == {
        "change_submit_simulation",
        "app_save_application",
        "assessment_submit_run",
        "assessment_cancel_run",
    }
    assert not writes & set(bare)
    assert not writes & set(with_store)
    assert "ops_list_collection_runs" not in bare
    assert "ops_list_collection_runs" in with_store
    assert len(bare) == 27


def _envelope_server(run):
    from mcp.server import MCPServer
    from pydantic import BaseModel, Field

    from hst.app.ai.mcp import register_mcp
    from hst.app.ai.registry import ToolRegistry, ToolSpec

    class ProbeInput(BaseModel):
        name: str = Field(description="The object name.", max_length=20)
        limit: int = Field(50, ge=1, le=200)

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="probe",
            version=1,
            description="Look up one object.",
            input_model=ProbeInput,
            permission="graph.read",
            kind="read",
            snapshot="none",
            run=run,
            surfaces=frozenset({"mcp"}),
        )
    )
    server = MCPServer("test")
    register_mcp(server, registry, principal=Principal.local())
    return server


async def test_an_envelope_tool_returns_is_error_for_a_tool_error():
    pytest.importorskip("mcp")
    from hst.app.ai.registry import ToolError

    def run(ctx, arguments):
        raise ToolError("not_found", f"no object named {arguments['name']}", field="name")

    res = await _envelope_server(run).call_tool("probe", {"name": "core9"})

    assert res.is_error is True
    assert res.structured_content == {
        "error": {
            "code": "not_found",
            "message": "no object named core9",
            "retryable": False,
            "field": "name",
        }
    }


async def test_an_envelope_tool_returns_the_result_and_publishes_the_input_model():
    pytest.importorskip("mcp")

    def run(ctx, arguments):
        assert ctx.surface == "mcp" and ctx.principal.role == "local"
        return {"result": arguments}

    server = _envelope_server(run)
    (tool,) = await server.list_tools()
    res = await server.call_tool("probe", {"name": "core1"})

    assert tool.description == "Look up one object."
    assert tool.input_schema["required"] == ["name"]
    assert tool.input_schema["properties"]["name"]["description"] == "The object name."
    assert tool.input_schema["properties"]["name"]["maxLength"] == 20
    assert tool.input_schema["properties"]["limit"]["default"] == 50
    assert res.is_error is False
    assert res.structured_content == {"result": {"name": "core1", "limit": 50}}


async def test_an_envelope_tool_that_raises_returns_an_internal_tool_error():
    pytest.importorskip("mcp")

    def run(ctx, arguments):
        raise RuntimeError("engine gone")

    res = await _envelope_server(run).call_tool("probe", {"name": "core1"})

    assert res.is_error is True
    assert res.structured_content["error"]["code"] == "internal"
    assert res.structured_content["error"]["message"] == "RuntimeError: engine gone"


def _server_for(input_model, run):
    """An MCP server that publishes one read tool `probe` over `input_model`."""
    from mcp.server import MCPServer

    from hst.app.ai.mcp import register_mcp
    from hst.app.ai.registry import ToolRegistry, ToolSpec

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="probe",
            version=1,
            description="Look up objects.",
            input_model=input_model,
            permission="graph.read",
            kind="read",
            snapshot="none",
            run=run,
            surfaces=frozenset({"mcp"}),
        )
    )
    server = MCPServer("test")
    register_mcp(server, registry, principal=Principal.local())
    return server


async def test_a_default_factory_runs_for_each_call_and_not_at_registration():
    pytest.importorskip("mcp")
    from pydantic import BaseModel, Field

    made: list[list[str]] = []

    def fresh() -> list[str]:
        made.append([])
        return made[-1]

    class TagsInput(BaseModel):
        tags: list[str] = Field(default_factory=fresh, description="Tags to match.")

    server = _server_for(TagsInput, lambda ctx, arguments: {"result": arguments})
    assert made == []

    (tool,) = await server.list_tools()
    first = await server.call_tool("probe", {})
    second = await server.call_tool("probe", {"tags": ["edge"]})

    assert "tags" not in tool.input_schema.get("required", [])
    assert tool.input_schema["properties"]["tags"]["description"] == "Tags to match."
    assert first.structured_content == {"result": {"tags": []}}
    assert second.structured_content == {"result": {"tags": ["edge"]}}
    assert made


def test_an_input_field_with_an_alias_is_refused_at_registration():
    pytest.importorskip("mcp")
    from pydantic import BaseModel, Field

    class AliasedInput(BaseModel):
        name: str = Field(alias="objectName")

    with pytest.raises(ValueError, match=r"AliasedInput\.name: an MCP tool input field takes no alias"):
        _server_for(AliasedInput, lambda ctx, arguments: "ok")


def _hst_ai_lines(caplog):
    return [(r.tool, r.outcome, r.surface) for r in caplog.records if r.name == "hst.ai"]


async def test_without_a_store_each_call_writes_one_log_line(monkeypatch, caplog):
    pytest.importorskip("mcp")
    from hst.mcp_server import build_server

    fakes.install(monkeypatch, fakes.FakeGraph([("RETURN d.hostname AS n", [{"n": 1}])]))
    monkeypatch.setattr(ai_mcp, "Settings", lambda: fakes.settings())
    caplog.set_level("INFO", logger="hst.ai")

    await build_server().call_tool("query_cypher", {"query": _GUARDED})
    await build_server().call_tool("query_cypher", {"query": "MATCH (d:Device) RETURN d"})

    assert _hst_ai_lines(caplog) == [
        ("query_cypher", "ok", "mcp"),
        ("query_cypher", "error", "mcp"),
    ]
    assert all(isinstance(r.latency_ms, int) for r in caplog.records if r.name == "hst.ai")


async def test_impact_evaluate_service_refuses_51_intents_before_any_session(monkeypatch):
    pytest.importorskip("mcp")
    from hst.mcp_server import build_server

    graph = fakes.install(monkeypatch, fakes.FakeGraph())
    monkeypatch.setattr(ai_mcp, "Settings", lambda: fakes.settings())
    intents = [{"kind": "fw_rule.add", "params": {"rulebase": "fw:LAN"}}] * 51

    # the input model holds the cap, so the call is refused as invalid_argument
    # before the tool opens a session
    res = await build_server().call_tool(
        "impact_evaluate_service", {"form": "requirement", "requirement": "sreq:app", "intents": intents}
    )

    assert res.is_error is True
    error = res.structured_content["error"]
    assert (error["code"], error["field"]) == ("invalid_argument", "intents")
    assert "at most 50 items" in error["message"]
    assert graph.session_kwargs == []


# --- catalogue tools through the server ----------------------------------------------


async def test_the_schema_conventions_teach_the_pinned_form_and_the_retention_default(monkeypatch):
    """The retention number in the conventions is literal text. A change of the
    cycle_keep_runs default fails this test until the text follows."""
    pytest.importorskip("mcp")

    fakes.install(monkeypatch, fakes.FakeGraph())
    monkeypatch.setattr(ai_mcp, "Settings", lambda: fakes.settings())
    server = mcp_server.build_server()

    res = await server.call_tool("query_catalog", {"mode": "schema"})
    conventions = " ".join(res.structured_content["result"]["conventions"])
    tools = {tool.name: tool for tool in await server.list_tools()}
    description = " ".join(tools["query_cypher"].description.split())

    assert res.is_error is False
    assert ":Latest" not in conventions
    assert "MATCH (d:Device:Latest)" not in conventions
    assert "$snap" in conventions
    assert "x.collection_ts = $snap" in conventions
    assert "coalesce(x.collection_ts" not in conventions
    assert "already pinned" not in conventions
    assert "needs no run filter" not in conventions
    assert "An unguarded MATCH reads every retained run" in conventions
    keep_runs = Settings.model_fields["cycle_keep_runs"].default
    assert f"{keep_runs} collection cycles by default" in conventions
    assert "already pinned" not in description
    assert "x.collection_ts = $snap" in description
    assert "coalesce(x.collection_ts" not in description
    assert "An unguarded MATCH reads every retained run" in description


async def test_query_cypher_refuses_the_latest_label_with_the_guard_form_before_any_session(monkeypatch):
    """The refusal of a query that names the Latest label teaches the indexed
    run pin and never claims the query is pinned."""
    pytest.importorskip("mcp")

    graph = fakes.install(monkeypatch, fakes.FakeGraph())
    monkeypatch.setattr(ai_mcp, "Settings", lambda: fakes.settings())

    query = "MATCH (d:Device:Latest) RETURN d"
    res = await mcp_server.build_server().call_tool("query_cypher", {"query": query})
    error = res.structured_content["error"]

    assert res.is_error is True
    assert error["code"] == "invalid_argument"
    assert error["field"] == "query"
    assert "x.collection_ts = $snap" in error["message"]
    assert "coalesce(x.collection_ts" not in error["message"]
    assert "already pinned" not in error["message"]
    assert graph.session_kwargs == []
    assert graph.calls == []


async def test_assessment_read_names_the_reason_it_could_not_open_the_app_store(monkeypatch):
    pytest.importorskip("mcp")
    from hst.app.store import pg

    def unreachable(dsn, ca_file):
        raise OSError("connection to db:5432 refused")

    fakes.install(monkeypatch, fakes.FakeGraph())
    monkeypatch.setattr(pg, "PgStore", unreachable)
    settings = fakes.settings(postgres_dsn="unused", postgres_ca_file="")
    monkeypatch.setattr(ai_mcp, "Settings", lambda: settings)

    res = await mcp_server.build_server().call_tool("assessment_read", {"mode": "list"})

    assert res.is_error is True
    assert res.structured_content == {
        "error": {
            "code": "engine_unavailable",
            "message": "the app store could not be read: OSError: connection to db:5432 refused",
            "retryable": True,
        }
    }


# --- the retired tool names ----------------------------------------------------------


def test_the_retired_names_are_the_nine_earlier_tools():
    assert mcp_server.RETIRED_TOOLS == _RETIRED


@pytest.mark.parametrize(
    "principal",
    [
        Principal.local(),
        Principal.local(store=True),
        Principal.for_token(user_id=1, role="viewer", scope="read"),
        Principal.for_token(user_id=1, role="admin", scope="read-write"),
    ],
    ids=["local", "local-with-store", "viewer-token", "admin-read-write-token"],
)
async def test_no_retired_name_is_published(principal):
    pytest.importorskip("mcp")

    names = {tool.name for tool in await mcp_server.build_server(principal).list_tools()}

    assert not names & set(_RETIRED)


async def test_each_replacement_is_a_published_catalogue_tool():
    pytest.importorskip("mcp")

    names = {tool.name for tool in await mcp_server.build_server(Principal.local(store=True)).list_tools()}

    assert {replacement.split(",")[0] for replacement in _RETIRED.values()} <= names


@pytest.mark.parametrize("name", sorted(_RETIRED))
async def test_a_retired_name_answers_unknown_tool_with_its_replacement_in_detail(monkeypatch, name):
    pytest.importorskip("mcp")

    graph = fakes.install(monkeypatch, fakes.FakeGraph())

    res = await mcp_server.build_server().call_tool(name, {"query": _GUARDED})

    assert res.is_error is True
    assert res.structured_content == {
        "error": {
            "code": "unknown_tool",
            "message": f"unknown tool {name}; its replacement is {_RETIRED[name]}",
            "retryable": False,
            "detail": _RETIRED[name],
        }
    }
    assert graph.session_kwargs == []


async def test_a_token_call_to_a_retired_name_answers_unknown_tool():
    pytest.importorskip("mcp")

    viewer = Principal.for_token(user_id=1, role="viewer", scope="read")

    res = await mcp_server.build_server(viewer).call_tool("cypher", {"query": _GUARDED})

    assert res.is_error is True
    assert res.structured_content["error"]["code"] == "unknown_tool"
    assert res.structured_content["error"]["detail"] == "query_cypher"


async def test_a_call_to_a_retired_name_writes_one_log_line(caplog):
    pytest.importorskip("mcp")

    caplog.set_level("INFO", logger="hst.ai")

    await mcp_server.build_server().call_tool("schema", {})

    lines = [r for r in caplog.records if r.name == "hst.ai"]
    assert [(r.tool, r.outcome, r.error_class) for r in lines] == [("schema", "error", "ToolError")]
