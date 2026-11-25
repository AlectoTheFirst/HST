"""`hst mcp`: the import guard, the store choice and the audit rows of local calls."""

import sys

import pytest
from tests.app.fakes import FakeStore
from tests.twin_tools_fakes import FakeGraph, install
from typer.testing import CliRunner

import hst.cli as cli
from hst import mcp_server

runner = CliRunner()

_GUARDED = "MATCH (d:Device) WHERE coalesce(d.collection_ts, $snap) = $snap RETURN d.hostname AS n"


@pytest.fixture
def no_store_settings(monkeypatch, tmp_path):
    """No POSTGRES_DSN in the environment and no .env in the working directory."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("POSTGRES_DSN", raising=False)


@pytest.fixture
def store_settings(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("POSTGRES_DSN", "postgresql+asyncpg://hst@localhost:5433/hst")


def test_without_the_mcp_package_hst_mcp_exits_2_with_the_install_hint(monkeypatch, no_store_settings):
    # None in sys.modules makes `import mcp.server` raise ImportError
    monkeypatch.setitem(sys.modules, "mcp.server", None)
    monkeypatch.setattr(mcp_server, "main", lambda: pytest.fail("the server must not start"))

    r = runner.invoke(cli.app, ["mcp"])

    assert r.exit_code == 2, r.output
    # the console wraps at the terminal width
    output = " ".join(r.output.split())
    assert "MCP dependencies missing" in output
    assert "pip install -e '.[mcp]'" in output


def test_without_a_store_hst_mcp_serves_without_opening_one(monkeypatch, no_store_settings):
    pytest.importorskip("mcp")
    started = []
    monkeypatch.setattr(mcp_server, "main", lambda: started.append(True))
    monkeypatch.setattr(cli, "_open_store", lambda settings, **_: pytest.fail("no store is configured"))

    r = runner.invoke(cli.app, ["mcp"])

    assert r.exit_code == 0, r.output
    assert started == [True]


def test_a_local_cypher_call_with_a_store_writes_one_cypher_event(monkeypatch, store_settings):
    pytest.importorskip("mcp")
    from mcp.server import MCPServer

    store = FakeStore()
    monkeypatch.setattr(cli, "_open_store", lambda settings, **_: store)
    install(monkeypatch, FakeGraph([("RETURN d.hostname AS n", [{"n": 1}])]))
    offered = []

    async def one_call(server):
        # stands in for the stdio loop: one tools/call, then the client hangs up
        offered.extend(t.name for t in await server.list_tools())
        await server.call_tool("query_cypher", {"query": _GUARDED})

    monkeypatch.setattr(MCPServer, "run_stdio_async", one_call)

    r = runner.invoke(cli.app, ["mcp"])

    assert r.exit_code == 0, r.output
    assert "query_cypher" in offered
    (event,) = store.cypher_events
    assert (event.origin, event.user_id, event.query, event.outcome) == ("mcp", None, _GUARDED, "ok")
    assert event.row_count == 1 and event.byte_count > 0
    (call,) = store.ai_events
    assert (call.origin, call.user_id, call.event, call.tool, call.outcome) == (
        "mcp",
        None,
        "tool.call",
        "query_cypher",
        "ok",
    )
    assert call.surface == "mcp"
    assert event.ai_step_id == call.step_id


def test_a_refused_cypher_call_with_a_store_is_recorded_as_rejected(monkeypatch, store_settings):
    pytest.importorskip("mcp")
    from mcp.server import MCPServer

    store = FakeStore()
    monkeypatch.setattr(cli, "_open_store", lambda settings, **_: store)
    install(monkeypatch, FakeGraph())

    async def one_call(server):
        await server.call_tool("query_cypher", {"query": "MATCH (d:Device:Latest) RETURN d"})

    monkeypatch.setattr(MCPServer, "run_stdio_async", one_call)

    r = runner.invoke(cli.app, ["mcp"])

    assert r.exit_code == 0, r.output
    assert [(e.origin, e.user_id, e.outcome) for e in store.cypher_events] == [("mcp", None, "rejected")]
    assert [(e.tool, e.outcome) for e in store.ai_events] == [("query_cypher", "error")]
