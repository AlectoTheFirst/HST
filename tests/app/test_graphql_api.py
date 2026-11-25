"""POST /api/graphql: authentication, CSRF, the run pin, batching, the
limits and the permission check, Neo4j faked at the context seam."""

from __future__ import annotations

import contextlib
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from graphql import FragmentDefinitionNode, GraphQLObjectType, parse
from tests.app.conftest import login
from tests.support.cputime import cpu_time

import hst.app.graphql.context as gql_context
from hst.app import security
from hst.app.graphql import limits
from hst.app.graphql.schema import schema
from hst.core import entity_read
from hst.core import filters as F
from hst.core import snapshot as snapshotmod

SNAP = 4242
OLD = 4000


def _endpoint(i: int, dev: str = "dev:sw1") -> dict:
    return {
        "uid": f"ep:{i}",
        "name": f"host-{i}",
        "label": f"host-{i}",
        "hostname": None,
        "mac": f"aa:bb:cc:00:00:0{i}",
        "vendor": "Synology",
        "kind": "client",
        "wired": True,
        "ip": None,
        "last_seen": 1_760_000_000_000,
        "ips": [f"10.0.0.{i}"],
        "attachments": [
            {"device": dev, "device_name": "sw1", "port": f"Port {i}", "ssid": None, "sites": ["ber1"]}
        ],
        "bd": "bd:vlan:fab0:10",
    }


class _Graph:
    """Answers each read by its query text, and records it with its parameters."""

    def __init__(self, endpoints: int = 3, fail: str | None = None):
        self.endpoints = [_endpoint(i) for i in range(endpoints)]
        self.calls: list[tuple[str, dict]] = []
        self.fail = fail
        self._lock = threading.Lock()

    def run(self, query, **params):
        text = getattr(query, "text", query)
        with self._lock:
            if "CyclePointer" in text:
                rows: list = [{"current": SNAP}]
            else:
                self.calls.append((text, params))
                rows = self._answer(text, params)
        if self.fail and self.fail in text:
            raise RuntimeError("bolt failure with internals in its text")

        class _R:
            def data(self_inner):
                return rows

        return _R()

    def _answer(self, text: str, params: dict) -> list:
        page = [{"uid": e["uid"], "sort_key": e["name"]} for e in self.endpoints]
        if text.startswith("\nMATCH (e:Endpoint:Obj)") and "count(" not in text:
            if "c_key" in params:
                page = [r for r in page if (r["sort_key"], r["uid"]) > (params["c_key"], params["c_uid"])]
            return page[: params["limit"]]
        if "count(" in text:
            return [{"n": len(self.endpoints)}]
        if text == entity_read.ENDPOINT_ROWS:
            return [e for e in self.endpoints if e["uid"] in params["uids"]]
        if text == entity_read.DEVICE_ROWS:
            return [
                {"uid": u, "name": "sw1", "hostname": "sw1", "role": "switch", "site": "site:ber1"}
                for u in params["uids"]
            ]
        if text == entity_read.SITE_ROWS:
            return [{"uid": u, "code": u.split(":", 1)[1], "kind": None} for u in params["uids"]]
        if text == entity_read.SEGMENT_ROWS:
            return [{"uid": u, "name": "users", "security_class": None} for u in params["uids"]]
        if text in entity_read.CHILDREN.values():
            return [
                {"parent": u, "children": [e["uid"] for e in self.endpoints][: params["first"]]}
                for u in params["uids"]
            ]
        return []

    def texts(self) -> list[str]:
        return [t for t, _ in self.calls]


@pytest.fixture
def graph(monkeypatch):
    g = _Graph()

    @contextlib.contextmanager
    def cm(settings):
        yield g

    monkeypatch.setattr(gql_context, "_session", cm)
    return g


@pytest.fixture
def retained(monkeypatch):
    def check(session, cts):
        if cts not in (SNAP, OLD):
            raise ValueError(f"unknown run {cts}")

    monkeypatch.setattr(snapshotmod, "require_retained", check)


async def _gql(client, query: str, variables: dict | None = None, **kwargs) -> httpx.Response:
    return await client.post("/api/graphql", json={"query": query, "variables": variables or {}}, **kwargs)


ENDPOINTS = (
    "{ endpoints(first: 2) { run totalCountCapped totalCountExact"
    " edges { cursor node { uid name ips } } pageInfo { hasNextPage endCursor } } }"
)


# --- authentication and CSRF ----------------------------------------------------------


async def test_graphql_requires_auth(client, graph):
    r = await _gql(client, ENDPOINTS)
    assert r.status_code == 401
    assert graph.calls == []


async def test_a_cookie_session_needs_the_csrf_header(app, graph):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as bare:
        r = await bare.post(
            "/api/login",
            json={"username": "vera", "password": "correct-horse-9"},
            headers={"X-HST-CSRF": "1"},
        )
        assert r.status_code == 200
        r = await _gql(bare, ENDPOINTS)
        assert r.status_code == 403 and r.json()["error"] == "missing CSRF header"
        r = await _gql(bare, ENDPOINTS, headers={"X-HST-CSRF": "1"})
        assert r.status_code == 200, r.text


async def test_a_query_in_the_url_is_refused(client, graph):
    await login(client, "vera")
    r = await client.get("/api/graphql", params={"query": "{ endpoints { totalCountCapped } }"})
    assert r.status_code == 405
    r = await client.get("/api/graphql", headers={"accept": "text/html"})
    assert r.status_code == 405
    assert graph.calls == []


async def _token(store, username: str, *, expires: timedelta = timedelta(days=1)) -> str:
    user = await store.get_user_by_username(username)
    now = datetime.now(UTC)
    token = f"pat-{username}-{expires.total_seconds()}"
    await store.create_access_token(security.token_hash(token), user.id, "gql", "read", now + expires, now)
    return token


async def test_a_personal_access_token_authenticates(app, store, graph):
    token = await _token(store, "vera")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as bare:
        auth = {"Authorization": f"Bearer {token}"}
        # a bearer request sends the CSRF header like every other POST
        r = await _gql(bare, ENDPOINTS, headers=auth)
        assert r.status_code == 403
        r = await _gql(bare, ENDPOINTS, headers={**auth, "X-HST-CSRF": "1"})
        assert r.status_code == 200, r.text
        assert r.json()["data"]["endpoints"]["totalCountCapped"] == 3
        for bad in ("Bearer nope", "Basic dmVyYTp4"):
            r = await _gql(bare, ENDPOINTS, headers={"Authorization": bad, "X-HST-CSRF": "1"})
            assert r.status_code == 401


async def test_an_expired_token_or_a_disabled_user_is_401(app, store, graph):
    expired = await _token(store, "vera", expires=timedelta(seconds=-1))
    otto = await _token(store, "otto")
    user = await store.get_user_by_username("otto")
    await store.update_user(user.id, disabled=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as bare:
        for token in (expired, otto):
            r = await _gql(bare, ENDPOINTS, headers={"Authorization": f"Bearer {token}", "X-HST-CSRF": "1"})
            assert r.status_code == 401


async def test_the_bearer_token_wins_over_the_cookie(client, graph):
    """A request with a session cookie and a bad bearer token is refused:
    the cookie is never the credential of a bearer request."""
    await login(client, "vera")
    r = await _gql(client, ENDPOINTS, headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


# --- reads, the run pin and batching --------------------------------------------------


async def test_a_page_of_endpoints_pinned_to_one_run(client, graph, retained):
    await login(client, "vera")
    r = await _gql(client, ENDPOINTS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "errors" not in body
    conn = body["data"]["endpoints"]
    assert (conn["run"], conn["totalCountCapped"], conn["totalCountExact"]) == (str(SNAP), 3, True)
    assert [e["node"]["uid"] for e in conn["edges"]] == ["ep:0", "ep:1"]
    assert conn["pageInfo"]["hasNextPage"] is True
    assert conn["pageInfo"]["endCursor"] == conn["edges"][-1]["cursor"]
    assert {p["snap"] for _, p in graph.calls} == {SNAP}

    after = conn["pageInfo"]["endCursor"]
    r = await _gql(
        client,
        "query($a: String) { endpoints(first: 2, after: $a)"
        " { edges { node { uid } } pageInfo { hasNextPage } } }",
        {"a": after},
    )
    conn = r.json()["data"]["endpoints"]
    assert [e["node"]["uid"] for e in conn["edges"]] == ["ep:2"]
    assert conn["pageInfo"]["hasNextPage"] is False


async def test_the_count_is_read_only_when_selected(client, graph):
    await login(client, "vera")
    r = await _gql(client, "{ endpoints { edges { node { uid } } } }")
    assert "errors" not in r.json(), r.json()
    assert not any("count(" in text for text in graph.texts())
    r = await _gql(client, "{ endpoints { ...C } } fragment C on EndpointConnection { totalCountCapped }")
    assert r.json()["data"]["endpoints"]["totalCountCapped"] == 3


async def test_nested_fields_are_read_once_per_level(client, graph):
    await login(client, "vera")
    q = """{ endpoints(first: 3) { edges { node {
              attachments { port device { hostname site { code } } }
              segment { name }
              addresses(first: 5) { uid } } } } }"""
    r = await _gql(client, q)
    assert r.status_code == 200, r.text
    assert "errors" not in r.json(), r.json()
    nodes = [e["node"] for e in r.json()["data"]["endpoints"]["edges"]]
    assert [n["attachments"][0]["device"]["site"]["code"] for n in nodes] == ["ber1"] * 3
    texts = graph.texts()
    # one read per object kind and per child list, however many endpoints the page holds
    for query in (
        entity_read.ENDPOINT_ROWS,
        entity_read.DEVICE_ROWS,
        entity_read.SITE_ROWS,
        entity_read.SEGMENT_ROWS,
        entity_read.ENDPOINT_ADDRESSES,
    ):
        assert texts.count(query) == 1, query
    assert {p["snap"] for _, p in graph.calls} == {SNAP}


async def test_a_named_run_pins_the_request(client, graph, retained):
    await login(client, "vera")
    r = await _gql(client, '{ endpoints(run: "4000") { run edges { node { uid } } } }')
    assert r.json()["data"]["endpoints"]["run"] == str(OLD)
    assert {p["snap"] for _, p in graph.calls} == {OLD}

    r = await _gql(client, '{ a: endpoints(run: "4000") { run } b: devices(run: "4242") { run } }')
    assert any("one request reads one run" in e["message"] for e in r.json()["errors"])

    r = await _gql(client, '{ endpoints(run: "123") { run } }')
    assert "unknown run: 123" in r.json()["errors"][0]["message"]
    r = await _gql(client, '{ endpoints(run: "x") { run } }')
    assert "is not a run id" in r.json()["errors"][0]["message"]


async def test_a_cursor_pins_its_run_and_its_filter(client, graph, retained):
    await login(client, "vera")
    f = F.parse_filter({"text": "host"})
    cur = F.Cursor(kind="endpoint", run=OLD, key="host-0", uid="ep:0", filter=f.fingerprint()).encode()
    q = 'query($a: String) { endpoints(filter: {text: "host"}, after: $a) { run edges { node { uid } } } }'
    r = await _gql(client, q, {"a": cur})
    assert r.json()["data"]["endpoints"]["run"] == str(OLD)
    r = await _gql(client, "query($a: String) { endpoints(after: $a) { run } }", {"a": cur})
    assert "another filter" in r.json()["errors"][0]["message"]
    r = await _gql(
        client, 'query($a: String) { devices(filter: {text: "host"}, after: $a) { run } }', {"a": cur}
    )
    assert "another list" in r.json()["errors"][0]["message"]
    r = await _gql(client, q.replace("after: $a", 'after: $a, run: "4242"'), {"a": cur})
    assert "another run" in r.json()["errors"][0]["message"]


async def test_the_filter_input_reaches_the_query(client, graph):
    await login(client, "vera")
    q = """{ endpoints(filter: {subnet: "10.0.0.0/24", textFields: [VENDOR, MAC], text: "syn",
                                 site: ["ber1"], lastSeenAfter: "2026-01-01T00:00:00Z"})
             { totalCountCapped } }"""
    r = await _gql(client, q)
    assert "errors" not in r.json(), r.json()
    _, params = graph.calls[0]
    assert (params["f_net_lo"], params["f_text"], params["f_site"]) == ("4:0a000000", "syn", ["site:ber1"])
    assert params["f_seen_after"] == 1_767_225_600_000


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ('{ endpoints(filter: {regex: "(a+)+"}) { run } }', "regex refused"),
        ('{ endpoints(filter: {rangeStart: "10.0.0.1"}) { run } }', "go together"),
        ('{ sites(filter: {ip: "10.0.0.1"}) { run } }', "site lists do not support"),
        ('{ endpoints(after: "garbage") { run } }', "invalid cursor"),
    ],
)
async def test_a_bad_filter_is_an_error_before_any_read(client, graph, query, message):
    await login(client, "vera")
    r = await _gql(client, query)
    assert message in r.json()["errors"][0]["message"]
    assert graph.calls == []


# --- limits ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ("{ endpoints(first: 101) { run } }", "first must be between 1 and 100"),
        ("{ endpoints(first: 0) { run } }", "first must be between 1 and 100"),
        (
            "{ endpoints { edges { node { addresses(first: 101) { uid } } } } }",
            "first must be between 1 and 100",
        ),
    ],
)
async def test_the_page_size_is_bounded(client, graph, query, message):
    await login(client, "vera")
    r = await _gql(client, query)
    assert message in r.json()["errors"][0]["message"]


async def test_a_costly_nested_query_is_refused_unread(client, graph):
    await login(client, "vera")
    q = "{ sites(first: 100) { edges { node { devices(first: 100) { endpoints(first: 100) { uid } } } } } }"
    r = await _gql(client, q)
    errors = r.json()["errors"]
    assert "above the limit of" in errors[0]["message"]
    assert graph.calls == []
    # a variable page size is costed at its maximum
    q = (
        "query($n: Int!) { sites(first: 2) { edges { node"
        " { devices(first: $n) { endpoints(first: 100) { uid } } } } } }"
    )
    r = await _gql(client, q, {"n": 1})
    assert "above the limit of" in r.json()["errors"][0]["message"]


def _cost(text: str) -> int:
    doc = parse(text)
    op = doc.definitions[0]
    frags = {d.name.value: d for d in doc.definitions if isinstance(d, FragmentDefinitionNode)}
    gql = schema._schema
    return limits.operation_cost(op.selection_set, gql.query_type, frags, gql)


def test_the_cost_counts_the_worst_case():
    assert _cost("{ endpoints { edges { node { uid } } } }") == limits.PAGE_DEFAULT
    assert _cost("{ endpoints(first: 10) { edges { node { segment { uid } } } } }") == 20
    assert _cost("{ endpoints(first: 10) { edges { node { attachments { device { uid } } } } } }") == 10 + 50
    assert _cost("{ sites(first: 2) { edges { node { devices(first: 3) { uid } } } } }") == 2 + 6
    assert (
        _cost(
            "{ sites(first: 2) { edges { node { ...D } } } } fragment D on Site { devices(first: 3) { uid } }"
        )
        == 2 + 6
    )


def test_the_cost_counts_a_fragment_for_each_spread():
    devices = " fragment D on Site { devices(first: 3) { uid } }"
    assert _cost("{ sites(first: 2) { edges { node { ...D ...D } } } }" + devices) == 2 + 6 + 6
    page = " fragment P on SiteConnection { edges { node { devices(first: 3) { uid } } } }"
    assert _cost("{ a: sites(first: 2) { ...P } b: sites(first: 5) { ...P } }" + page) == 2 + 6 + 5 + 15


def test_the_cost_of_a_fragment_cycle_ends():
    q = (
        "{ sites(first: 2) { edges { node { ...A } } } }"
        " fragment A on Site { devices(first: 3) { ...B } }"
        " fragment B on Device { site { ...A } }"
    )
    assert _cost(q) == 2 + 6 + 6


def _nested_fragments(levels: int) -> str:
    """A document whose fragment `F0` expands to more than 2**levels selections."""
    inner = " ".join(f"fragment F{i} on Query {{ ...F{i + 1} ...F{i + 1} }}" for i in range(levels))
    return f"{{ ...F0 }} {inner} fragment F{levels} on Query {{ __typename }}"


def test_the_expansion_counts_a_fragment_for_each_spread():
    assert limits.expanded_selections(parse("{ __typename }")) == 1
    assert limits.expanded_selections(parse("{ ...T ...T } fragment T on Query { __typename }")) == 4
    assert limits.expanded_selections(parse(_nested_fragments(9))) == 3 * 2**9 - 1
    assert limits.expanded_selections(parse(_nested_fragments(190))) == 3 * 2**190 - 1
    assert limits.expanded_selections(parse("{ ...A } fragment A on Query { ...A }")) is None


async def test_a_document_of_nested_fragments_is_refused(client, graph):
    await login(client, "vera")
    r = await _gql(client, _nested_fragments(9))
    assert r.json() == {"data": {"__typename": "Query"}}
    with cpu_time(all_threads=True) as spent:
        r = await _gql(client, _nested_fragments(22))
    assert spent.seconds < 5
    messages = [e["message"] for e in r.json()["errors"]]
    assert messages == [f"the query expands to more than {limits.MAX_SELECTIONS} selections"]
    assert graph.calls == []


async def test_a_fragment_cycle_is_refused(client, graph):
    await login(client, "vera")
    r = await _gql(client, "{ ...A } fragment A on Query { ...B } fragment B on Query { ...A }")
    assert [e["message"] for e in r.json()["errors"]] == ["Cannot spread fragment 'A' within itself via 'B'."]
    # each of 11 fragments spreads the 10 others
    names = [f"F{i}" for i in range(11)]
    each = " ".join(
        f"fragment {name} on Query {{ {' '.join(f'...{other}' for other in names if other != name)} }}"
        for name in names
    )
    with cpu_time(all_threads=True) as spent:
        r = await _gql(client, "{ ...F0 } " + each)
    assert spent.seconds < 5
    assert r.json()["errors"][0]["message"] == "Cannot spread fragment 'F0' within itself via 'F1'."
    # the second definition of A replaces the first
    r = await _gql(client, "{ ...A } fragment A on Query { __typename } fragment A on Query { ...A }")
    assert [e["message"] for e in r.json()["errors"]] == ["the query spreads a fragment within itself"]


@pytest.mark.parametrize(
    "query",
    [
        "{ ...Nope }",
        "{ sites { ...Nope } }",
        "{ ... on Query { ...Nope } }",
        "{ ...A } fragment A on Query { ...Nope }",
        "{ __typename } fragment A on Query { ...Nope }",
    ],
)
async def test_a_spread_of_an_undefined_fragment_is_refused(client, graph, query):
    await login(client, "vera")
    r = await _gql(client, query)
    assert [e["message"] for e in r.json()["errors"]] == ["Unknown fragment 'Nope'."]
    assert graph.calls == []


@pytest.mark.parametrize(
    "query",
    [
        "{ }",
        "{ sites { } }",
        "{ ... on Query { } }",
        "{ ...A } fragment A on Query { }",
        "{ __typename } fragment A on Query { }",
    ],
)
async def test_an_empty_selection_set_is_refused(client, graph, query):
    await login(client, "vera")
    r = await _gql(client, query)
    assert [e["message"] for e in r.json()["errors"]] == ["the query holds an empty selection set"]
    assert graph.calls == []


def _nested_inline_fragments(fragments: int, levels: int) -> str:
    """A chain of `fragments` fragments, each with `levels` nested inline fragments."""
    parts = ["{ ...F0 }"]
    for i in range(fragments):
        inner = f"...F{i + 1}" if i + 1 < fragments else "__typename"
        parts.append(f"fragment F{i} on Query {{ {'... { ' * levels}{inner}{' }' * levels} }}")
    return " ".join(parts)


async def test_fragments_nested_past_the_parser_bound_are_refused(client, graph):
    await login(client, "vera")
    r = await _gql(client, _nested_inline_fragments(2, 98))
    assert r.json() == {"data": {"__typename": "Query"}}
    r = await _gql(client, _nested_inline_fragments(3, 190))
    assert [e["message"] for e in r.json()["errors"]] == ["Validation aborted."]


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ("{ ...A } fragment A on Nope { __typename }", "Unknown type 'Nope'."),
        ("{ ... on Nope { __typename } }", "Unknown type 'Nope'."),
        (
            "{ __typename } query B { __typename }",
            "This anonymous operation must be the only defined operation.",
        ),
        ("query A { __typename } query A { __typename }", "There can be only one operation named 'A'."),
        ("{ sites(first: $n) { run } }", "Variable '$n' is not defined."),
        ("{ ...A @nope } fragment A on Query { __typename }", "Unknown directive '@nope'."),
    ],
)
async def test_an_invalid_document_gets_its_validation_message(client, graph, query, message):
    await login(client, "vera")
    r = await _gql(client, query)
    assert [e["message"] for e in r.json()["errors"]] == [message]
    assert graph.calls == []


@pytest.mark.parametrize(
    ("query", "data"),
    [
        ("query($n: Int) { sites(first: $n) { run } }", {"sites": {"run": str(SNAP)}}),
        ("{ ...A @skip(if: true) } fragment A on Query { __typename }", {}),
    ],
)
async def test_a_variable_page_size_and_a_directive_on_a_spread_pass_the_limiters(client, graph, query, data):
    await login(client, "vera")
    r = await _gql(client, query)
    assert r.json() == {"data": data}


async def test_depth_aliases_and_tokens_are_bounded(client, graph):
    await login(client, "vera")
    nested = "uid"
    for _ in range(limits.MAX_DEPTH):
        nested = f"prefix {{ addresses(first: 1) {{ {nested} }} }}"
    deep = f"{{ ipAddresses(first: 1) {{ edges {{ node {{ {nested} }} }} }} }}"
    r = await _gql(client, deep)
    assert "exceeds maximum operation depth" in r.json()["errors"][0]["message"]
    aliases = (
        "{ " + " ".join(f"a{i}: sites(first: 1) {{ run }}" for i in range(limits.MAX_ALIASES + 1)) + " }"
    )
    r = await _gql(client, aliases)
    assert "aliases" in r.json()["errors"][0]["message"].lower()
    tokens = "{ sites(first: 1) { run " + "run " * limits.MAX_TOKENS + "} }"
    r = await _gql(client, tokens)
    assert "token" in r.json()["errors"][0]["message"].lower()
    assert graph.calls == []


async def test_introspection_passes_the_depth_limit(client, graph):
    await login(client, "vera")
    q = """{ __schema { types { name fields { name type { name
             ofType { name ofType { name ofType { name } } } } } } } }"""
    r = await _gql(client, q)
    assert "errors" not in r.json(), r.json()


# --- the schema and permissions -------------------------------------------------------


def test_the_schema_holds_queries_only():
    assert schema._schema.mutation_type is None
    assert schema._schema.subscription_type is None


def test_every_type_declares_its_permission():
    names = {
        name
        for name, t in schema._schema.type_map.items()
        if isinstance(t, GraphQLObjectType) and not name.startswith("__")
    }
    assert names <= set(limits.TYPE_PERMISSIONS), names - set(limits.TYPE_PERMISSIONS)


async def test_a_mutation_is_refused(client, graph):
    await login(client, "vera")
    r = await _gql(client, "mutation { endpoints { run } }")
    assert r.json()["errors"]


async def test_every_field_checks_the_permission(client, graph, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(gql_context, "permissions_for", lambda role: frozenset())
    r = await _gql(client, ENDPOINTS)
    body = r.json()
    assert body["data"] is None
    assert body["errors"][0]["message"] == "requires permission: graph.read"
    assert graph.calls == []
    # introspection stays open to an authenticated caller
    r = await _gql(client, "{ __typename }")
    assert r.json()["data"] == {"__typename": "Query"}


async def test_an_unexpected_error_is_masked(client, monkeypatch):
    g = _Graph(fail="UNWIND $uids")

    @contextlib.contextmanager
    def cm(settings):
        yield g

    monkeypatch.setattr(gql_context, "_session", cm)
    await login(client, "vera")
    r = await _gql(client, ENDPOINTS)
    messages = [e["message"] for e in r.json()["errors"]]
    assert messages and all(m == "Unexpected error." for m in messages)
    assert "internals" not in r.text
