"""The MCP HTTP transport at /api/mcp, personal access tokens and the stdio bridge."""

from __future__ import annotations

import io
import json
import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from tests.app.conftest import PASSWORD, login
from tests.twin_tools_fakes import FakeGraph, install
from typer.testing import CliRunner

from hst import mcp_bridge
from hst.app import security
from hst.app.permissions import ROLE_PERMISSIONS
from hst.app.routes import mcp_http

pytest.importorskip("mcp")

GUARDED = "MATCH (d:Device) WHERE coalesce(d.collection_ts, $snap) = $snap RETURN d.hostname AS n"
TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def _bare(app) -> httpx.AsyncClient:
    """A client with no CSRF header and no session: what an MCP client sends."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _enable(store, enabled: bool = True) -> None:
    await store.put_setting(mcp_http.SETTINGS_KEY, {"enabled": enabled}, b"")


async def _issue(app, username: str, **body) -> dict:
    """Issue a token through the route, signed in as `username`."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", headers={"X-HST-CSRF": "1"}
    ) as client:
        await login(client, username)
        r = await client.post("/api/access-tokens", json={"name": "laptop", **body})
    assert r.status_code == 201, r.text
    return r.json()


async def _cookie_login(client: httpx.AsyncClient, username: str) -> None:
    """Sign in on a client that sends no CSRF header by default."""
    r = await client.post(
        "/api/login", json={"username": username, "password": PASSWORD}, headers={"X-HST-CSRF": "1"}
    )
    assert r.status_code == 200, r.text


async def _mcp(app, token: str | None, message: dict, *, method: str = "POST") -> httpx.Response:
    headers = dict(MCP_HEADERS)
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    async with _bare(app) as client:
        return await client.request(method, "/api/mcp", content=json.dumps(message), headers=headers)


async def _tool_names(app, token: str) -> list[str]:
    r = await _mcp(app, token, TOOLS_LIST)
    assert r.status_code == 200, r.text
    return [tool["name"] for tool in r.json()["result"]["tools"]]


def _call(name: str, arguments: dict, request_id: int = 2) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


# --- criterion 1: the setting -----------------------------------------------------------


async def test_with_the_setting_absent_api_mcp_is_404(app, store):
    token = (await _issue(app, "otto"))["token"]

    for method in ("POST", "GET"):
        r = await _mcp(app, token, TOOLS_LIST, method=method)
        assert r.status_code == 404, (method, r.text)


async def test_with_the_setting_off_api_mcp_is_404(app, store):
    token = (await _issue(app, "otto"))["token"]
    await _enable(store, False)

    r = await _mcp(app, token, TOOLS_LIST)

    assert r.status_code == 404


async def test_an_admin_turns_the_transport_on_and_off(app, store, client):
    await login(client, "ada")
    assert (await client.get("/api/settings/mcp")).json() == {"mcp_http_enabled": False}

    r = await client.put("/api/settings/mcp", json={"mcp_http_enabled": True})

    assert r.json() == {"mcp_http_enabled": True}
    assert await mcp_http.http_enabled(store) is True
    await client.put("/api/settings/mcp", json={"mcp_http_enabled": False})
    assert await mcp_http.http_enabled(store) is False


async def test_a_request_adds_no_session_manager_line_to_the_app_log(app, store, caplog):
    token = (await _issue(app, "otto"))["token"]
    await _enable(store)
    caplog.set_level(logging.INFO)

    await _tool_names(app, token)

    assert [r.getMessage() for r in caplog.records if r.name == mcp_http.SESSION_MANAGER_LOGGER] == []


async def test_the_transport_takes_post_only(app, store):
    token = (await _issue(app, "otto"))["token"]
    await _enable(store)

    r = await _mcp(app, token, TOOLS_LIST, method="GET")

    assert r.status_code == 405
    assert r.headers["allow"] == "POST"


# --- criterion 2: 401 and 403, and the per-user tool list -------------------------------


@pytest.mark.parametrize("authorization", [None, "Bearer", "Basic dXNlcjpwdw==", "Bearer not-a-token"])
async def test_a_post_without_an_accepted_bearer_token_is_refused(app, store, authorization):
    await _enable(store)
    headers = dict(MCP_HEADERS)
    if authorization is not None:
        headers["Authorization"] = authorization
    async with _bare(app) as client:
        r = await client.post("/api/mcp", content=json.dumps(TOOLS_LIST), headers=headers)

    # a request with no bearer token is not CSRF-exempt, so without the header
    # the guard answers first; with a bearer token the endpoint answers
    if security.bearer_token(authorization) is None:
        assert r.status_code == 403
        assert r.json()["error"] == "missing CSRF header"
    else:
        assert r.status_code == 401
        assert r.headers["www-authenticate"].startswith("Bearer")


async def test_a_missing_token_with_the_csrf_header_is_401(app, store):
    await _enable(store)
    async with _bare(app) as client:
        r = await client.post(
            "/api/mcp", content=json.dumps(TOOLS_LIST), headers={**MCP_HEADERS, "X-HST-CSRF": "1"}
        )

    assert r.status_code == 401


async def test_a_revoked_token_is_401(app, store, client):
    issued = await _issue(app, "otto")
    await _enable(store)
    assert (await _mcp(app, issued["token"], TOOLS_LIST)).status_code == 200

    await login(client, "otto")
    assert (await client.delete(f"/api/access-tokens/{issued['id']}")).status_code == 204

    assert (await _mcp(app, issued["token"], TOOLS_LIST)).status_code == 401


async def test_an_expired_token_is_401(app, store):
    otto = await store.get_user_by_username("otto")
    now = datetime.now(UTC)
    await store.create_access_token(
        security.token_hash("expired-token"), otto.id, "old", "read", now - timedelta(seconds=1), now
    )
    await _enable(store)

    r = await _mcp(app, "expired-token", TOOLS_LIST)

    assert r.status_code == 401


async def test_a_disabled_users_token_is_401(app, store):
    token = (await _issue(app, "otto"))["token"]
    otto = await store.get_user_by_username("otto")
    await store.update_user(otto.id, disabled=True)
    await _enable(store)

    assert (await _mcp(app, token, TOOLS_LIST)).status_code == 401


async def test_a_token_whose_user_lacks_agent_ask_is_403(app, store, monkeypatch):
    token = (await _issue(app, "vera"))["token"]
    await _enable(store)
    # the role lost agent.ask after the token was issued
    monkeypatch.setitem(ROLE_PERMISSIONS, "viewer", frozenset({"graph.read"}))

    r = await _mcp(app, token, TOOLS_LIST)

    assert r.status_code == 403
    assert r.json()["error"] == "requires permission: agent.ask"


async def test_a_viewer_token_lists_no_query_cypher(app, store):
    viewer = (await _issue(app, "vera"))["token"]
    operator = (await _issue(app, "otto"))["token"]
    await _enable(store)

    viewer_tools = await _tool_names(app, viewer)
    operator_tools = await _tool_names(app, operator)

    assert "query_cypher" not in viewer_tools
    assert "cypher" not in viewer_tools
    assert "query_catalog" in viewer_tools
    assert "query_cypher" in operator_tools


async def test_a_viewer_token_cannot_call_query_cypher(app, store):
    token = (await _issue(app, "vera"))["token"]
    await _enable(store)

    r = await _mcp(app, token, _call("query_cypher", {"query": GUARDED}))

    assert r.status_code == 200
    body = r.json()
    assert body["result"]["isError"] is True
    assert store.cypher_events == []


async def test_the_token_principal_carries_the_users_permissions_and_the_token_scope(app, store, monkeypatch):
    from hst import mcp_server

    token = (await _issue(app, "otto", scope="read-write"))["token"]
    await _enable(store)
    built = []
    real = mcp_server.build_server

    def spy(principal, **kwargs):
        built.append(principal)
        return real(principal, **kwargs)

    monkeypatch.setattr(mcp_server, "build_server", spy)

    assert (await _mcp(app, token, TOOLS_LIST)).status_code == 200

    (principal,) = built
    otto = await store.get_user_by_username("otto")
    assert principal.user_id == otto.id
    assert principal.origin == "mcp"
    assert principal.scope == "read-write"
    assert principal.permissions == ROLE_PERMISSIONS["operator"]


# --- criterion 3: CSRF --------------------------------------------------------------------


async def test_a_cookie_session_post_without_the_csrf_header_is_rejected(app, store):
    await _enable(store)
    async with _bare(app) as client:
        await _cookie_login(client, "otto")
        r = await client.post("/api/mcp", content=json.dumps(TOOLS_LIST), headers=MCP_HEADERS)

    assert r.status_code == 403
    assert r.json()["error"] == "missing CSRF header"


async def test_a_cookie_session_post_with_the_csrf_header_is_401(app, store):
    """The session cookie is not a credential of the transport."""
    await _enable(store)
    async with _bare(app) as client:
        await _cookie_login(client, "otto")
        r = await client.post(
            "/api/mcp", content=json.dumps(TOOLS_LIST), headers={**MCP_HEADERS, "X-HST-CSRF": "1"}
        )

    assert r.status_code == 401


# --- criterion 4: audit -------------------------------------------------------------------


async def test_query_cypher_writes_cypher_events_with_the_token_user_and_origin_mcp(app, store, monkeypatch):
    install(monkeypatch, FakeGraph([("RETURN d.hostname AS n", [{"n": "core1"}])]))
    token = (await _issue(app, "otto"))["token"]
    await _enable(store)

    r = await _mcp(app, token, _call("query_cypher", {"query": GUARDED}))

    assert r.status_code == 200, r.text
    result = r.json()["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["result"]["data"] == [{"row": ["core1"]}]
    otto = await store.get_user_by_username("otto")
    (event,) = store.cypher_events
    assert (event.user_id, event.origin, event.query, event.outcome) == (otto.id, "mcp", GUARDED, "ok")
    (call,) = store.ai_events
    assert (call.user_id, call.origin, call.surface, call.event, call.tool, call.outcome) == (
        otto.id,
        "mcp",
        "mcp",
        "tool.call",
        "query_cypher",
        "ok",
    )
    assert event.ai_step_id == call.step_id


async def test_a_retired_tool_name_answers_unknown_tool_with_its_replacement(app, store, monkeypatch):
    graph = install(monkeypatch, FakeGraph())
    token = (await _issue(app, "otto"))["token"]
    await _enable(store)

    r = await _mcp(app, token, _call("cypher", {"query": GUARDED}))

    assert r.status_code == 200, r.text
    result = r.json()["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["error"]["code"] == "unknown_tool"
    assert result["structuredContent"]["error"]["detail"] == "query_cypher"
    assert graph.session_kwargs == []
    assert store.cypher_events == []
    otto = await store.get_user_by_username("otto")
    (call,) = store.ai_events
    assert (call.user_id, call.tool, call.outcome, call.error_class) == (
        otto.id,
        "cypher",
        "error",
        "ToolError",
    )


async def test_a_refused_query_is_recorded_with_the_token_user(app, store, monkeypatch):
    install(monkeypatch, FakeGraph())
    token = (await _issue(app, "otto"))["token"]
    await _enable(store)

    r = await _mcp(app, token, _call("query_cypher", {"query": "MATCH (d:Device) RETURN d"}))

    assert r.json()["result"]["isError"] is True
    otto = await store.get_user_by_username("otto")
    assert [(e.user_id, e.origin, e.outcome) for e in store.cypher_events] == [(otto.id, "mcp", "rejected")]


async def test_a_token_use_moves_last_used_forward(app, store):
    issued = await _issue(app, "otto")
    assert issued["last_used_at"] is None
    await _enable(store)

    await _mcp(app, issued["token"], TOOLS_LIST)

    otto = await store.get_user_by_username("otto")
    (token,) = await store.list_access_tokens(otto.id)
    assert token.last_used_at is not None


# --- criterion 5: the bridge --------------------------------------------------------------


async def _bridge(app, token: str, messages: list[dict | str]) -> list[bytes]:
    lines = [m if isinstance(m, str) else json.dumps(m) for m in messages]
    stdin = io.BytesIO("".join(line + "\n" for line in lines).encode())
    stdout = io.BytesIO()
    await mcp_bridge.relay("http://t/api/mcp", token, stdin, stdout, transport=httpx.ASGITransport(app=app))
    return stdout.getvalue().splitlines()


async def test_the_bridge_relays_tools_list_unchanged(app, store):
    token = (await _issue(app, "otto"))["token"]
    await _enable(store)
    direct = await _mcp(app, token, TOOLS_LIST)

    (relayed,) = await _bridge(app, token, [TOOLS_LIST])

    assert relayed == direct.content.strip()
    assert "query_cypher" in [tool["name"] for tool in json.loads(relayed)["result"]["tools"]]


async def test_the_bridge_answers_an_initialize_and_sends_the_negotiated_version(app, store):
    token = (await _issue(app, "vera"))["token"]
    await _enable(store)
    initialize = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    }
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}

    stdin = io.BytesIO((json.dumps(initialize) + "\n").encode())
    stdout = io.BytesIO()
    seen: list[str | None] = []

    async def record(request: httpx.Request) -> None:
        seen.append(request.headers.get(mcp_bridge.PROTOCOL_HEADER))

    transport = httpx.ASGITransport(app=app)
    bridge = mcp_bridge.Bridge("http://t/api/mcp", token, stdout.write, transport=transport)
    bridge._client.event_hooks["request"] = [record]
    try:
        await bridge.forward(stdin.readline().strip())
        await bridge.forward(json.dumps(initialized).encode())
        await bridge.forward(json.dumps(TOOLS_LIST).encode())
    finally:
        await bridge.aclose()

    answers = [json.loads(line) for line in stdout.getvalue().splitlines()]
    # the notification has no answer
    assert [a["id"] for a in answers] == [0, 1]
    version = answers[0]["result"]["protocolVersion"]
    assert seen == [None, version, version]


async def test_the_bridge_answers_an_http_error_with_a_json_rpc_error(app, store):
    issued = await _issue(app, "otto")
    await _enable(store)
    otto = await store.get_user_by_username("otto")
    await store.delete_access_token(otto.id, issued["id"])

    (line,) = await _bridge(app, issued["token"], [TOOLS_LIST])

    answer = json.loads(line)
    assert answer["id"] == 1
    assert answer["error"]["code"] == mcp_bridge.TRANSPORT_ERROR
    assert "HTTP 401" in answer["error"]["message"]


async def test_the_bridge_answers_a_line_that_is_not_json_with_a_parse_error(app, store):
    (line,) = await _bridge(app, "any", ["{not json"])

    answer = json.loads(line)
    assert answer["id"] is None
    assert answer["error"]["code"] == mcp_bridge.PARSE_ERROR


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://hst.example/api/mcp", True),
        ("http://localhost:8000/api/mcp", True),
        ("http://127.0.0.1/api/mcp", True),
        ("http://hst.example/api/mcp", False),
        ("ftp://hst.example/api/mcp", False),
        ("hst.example/api/mcp", False),
    ],
)
def test_the_bridge_sends_the_token_only_over_https_or_to_loopback(url, ok):
    if ok:
        assert mcp_bridge.check_url(url) == url
    else:
        with pytest.raises(mcp_bridge.BridgeError):
            mcp_bridge.check_url(url)


def test_hst_mcp_remote_without_a_token_exits_2(monkeypatch):
    import hst.cli as cli

    monkeypatch.delenv(mcp_bridge.TOKEN_ENV, raising=False)
    monkeypatch.setattr(mcp_bridge, "relay", lambda *a, **k: pytest.fail("the bridge must not start"))

    r = CliRunner().invoke(cli.app, ["mcp", "--remote", "https://hst.example/api/mcp"])

    assert r.exit_code == 2
    assert mcp_bridge.TOKEN_ENV in r.output


def test_hst_mcp_remote_relays_with_the_token_from_the_environment(monkeypatch):
    import hst.cli as cli

    started = []

    async def relay(url, token, stdin, stdout, **kwargs):
        started.append((url, token))

    monkeypatch.setenv(mcp_bridge.TOKEN_ENV, "t0ken")
    monkeypatch.setattr(mcp_bridge, "relay", relay)

    r = CliRunner().invoke(cli.app, ["mcp", "--remote", "https://hst.example/api/mcp"])

    assert r.exit_code == 0, r.output
    assert started == [("https://hst.example/api/mcp", "t0ken")]


# --- criterion 6: the scope ---------------------------------------------------------------


async def test_a_token_created_without_a_scope_has_scope_read(app, store):
    issued = await _issue(app, "otto")

    assert issued["scope"] == "read"
    otto = await store.get_user_by_username("otto")
    (token,) = await store.list_access_tokens(otto.id)
    assert token.scope == "read"


async def test_the_scope_chosen_at_creation_is_kept_and_listed(app, store, client):
    await _issue(app, "otto", scope="read-write")
    await login(client, "otto")

    r = await client.get("/api/access-tokens")

    assert [(t["name"], t["scope"]) for t in r.json()["tokens"]] == [("laptop", "read-write")]


async def test_an_unknown_scope_is_refused(app, client):
    await login(client, "otto")

    r = await client.post("/api/access-tokens", json={"name": "x", "scope": "admin"})

    assert r.status_code == 422


@pytest.mark.parametrize("method", ["PATCH", "PUT"])
async def test_the_scope_cannot_be_changed_after_creation(app, store, client, method):
    issued = await _issue(app, "otto")
    await login(client, "otto")

    r = await client.request(method, f"/api/access-tokens/{issued['id']}", json={"scope": "read-write"})

    assert r.status_code == 405
    otto = await store.get_user_by_username("otto")
    (token,) = await store.list_access_tokens(otto.id)
    assert token.scope == "read"


# --- the token routes ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "token"),
    [
        ("Bearer abc", "abc"),
        ("bearer abc", "abc"),
        ("  Bearer   abc  ", "abc"),
        (None, None),
        ("", None),
        ("Bearer", None),
        ("Bearer ", None),
        ("Bearer a b", None),
        ("Basic abc", None),
        ("Bearerabc", None),
    ],
)
def test_the_bearer_token_is_read_from_the_authorization_header(header, token):
    assert security.bearer_token(header) == token


async def test_the_token_text_is_returned_once_and_stored_hashed(app, store, client):
    issued = await _issue(app, "otto")
    await login(client, "otto")

    listed = (await client.get("/api/access-tokens")).json()

    assert "token" not in listed["tokens"][0]
    assert listed["mcp_http_enabled"] is False
    assert list(store.access_tokens) == [security.token_hash(issued["token"])]


async def test_a_user_sees_and_revokes_only_their_own_tokens(app, store, client):
    issued = await _issue(app, "otto")
    await login(client, "vera")

    assert (await client.get("/api/access-tokens")).json()["tokens"] == []
    assert (await client.delete(f"/api/access-tokens/{issued['id']}")).status_code == 404
    otto = await store.get_user_by_username("otto")
    assert len(await store.list_access_tokens(otto.id)) == 1


async def test_a_blank_name_is_refused(app, client):
    await login(client, "otto")

    r = await client.post("/api/access-tokens", json={"name": "   "})

    assert r.status_code == 422


async def test_a_user_holds_at_most_the_token_cap(app, store, client, monkeypatch):
    from hst.app.routes import access_tokens

    monkeypatch.setattr(access_tokens, "MAX_TOKENS_PER_USER", 2)
    await login(client, "otto")
    for name in ("a", "b"):
        assert (await client.post("/api/access-tokens", json={"name": name})).status_code == 201

    r = await client.post("/api/access-tokens", json={"name": "c"})

    assert r.status_code == 409
