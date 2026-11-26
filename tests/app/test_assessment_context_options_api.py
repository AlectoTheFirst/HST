"""GET /api/assessment-options lists the IdentityGroup and ZpaAppSegment nodes of a pinned run."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from tests.app.conftest import login

from hst import path
from hst.app.ai.registry import ToolContext
from hst.applications import generator_tools
from hst.assessment import discovery
from hst.core import snapshot as snapshotmod

NODES = [
    {
        "uid": "zpa:t:idp:okta-finance",
        "labels": ["Obj", "App", "IdentityGroup"],
        "name": "Finance",
        "idp_name": "Okta",
    },
    {
        "uid": "zpa:t:idp:azure-finance",
        "labels": ["Obj", "App", "IdentityGroup"],
        "name": "Finance",
        "idp_name": "Azure",
    },
    {"uid": "zpa:t:seg:101", "labels": ["Obj", "ZpaAppSegment"], "name": "Finance portal", "idp_name": None},
    {"uid": "dev:finance-fw", "labels": ["Obj", "Device"], "name": "finance-fw", "idp_name": None},
]


@pytest.fixture
def graph(monkeypatch):
    reads = []

    @contextmanager
    def session(_settings, **_kwargs):
        yield object()

    monkeypatch.setattr(discovery.db, "session", session)
    monkeypatch.setattr(discovery.service, "snapshot_reference", lambda settings, value: {"snapshot": value})
    monkeypatch.setattr(discovery.snapshotmod, "resolve", lambda raw, settings, cts: SimpleNamespace(cts=cts))

    def read(session, query, **params):
        reads.append((session.cts, query, params))
        if query != discovery._CONTEXT_OBJECTS:
            raise AssertionError(query)
        rows = [
            {key: node[key] for key in ("uid", "labels", "name", "idp_name")}
            for node in NODES
            if any(label in params["labels"] for label in node["labels"])
            and (params["uid"] is None or node["uid"] == params["uid"])
            and (not params["q"] or params["q"] in node["name"].casefold() or params["q"] in node["uid"])
        ]
        return rows[: params["limit"]]

    monkeypatch.setattr(path, "_read", read)
    return reads


async def test_identity_groups_are_listed_by_name_at_the_pinned_run(client, graph):
    assert (await client.get("/api/assessment-options?snapshot=300&kind=identity")).status_code == 401
    await login(client, "vera")
    response = await client.get("/api/assessment-options", params={"snapshot": "300", "kind": "identity"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["snapshot"] == "300"
    assert body["truncated"] is False
    assert body["items"] == [
        {
            "uid": "zpa:t:idp:okta-finance",
            "name": "Finance",
            "kind": "identity",
            "source": "Okta",
            "selectable": True,
        },
        {
            "uid": "zpa:t:idp:azure-finance",
            "name": "Finance",
            "kind": "identity",
            "source": "Azure",
            "selectable": True,
        },
    ]
    assert [(cts, params["labels"]) for cts, _query, params in graph] == [(300, ["IdentityGroup"])]


async def test_segments_match_the_query_text_and_the_limit_sets_truncated(client, graph):
    await login(client, "vera")
    response = await client.get(
        "/api/assessment-options", params={"snapshot": "300", "kind": "segment", "q": "PORTAL"}
    )
    assert response.status_code == 200, response.text
    assert [(item["uid"], item["kind"]) for item in response.json()["items"]] == [
        ("zpa:t:seg:101", "segment")
    ]
    assert graph[-1][2]["labels"] == ["ZpaAppSegment"]
    assert graph[-1][2]["q"] == "portal"
    response = await client.get(
        "/api/assessment-options", params={"snapshot": "300", "kind": "identity", "limit": 1}
    )
    assert response.json()["truncated"] is True
    assert len(response.json()["items"]) == 1


async def test_a_uid_resolves_one_segment(client, graph):
    await login(client, "vera")
    response = await client.get(
        "/api/assessment-options", params={"snapshot": "300", "kind": "segment", "uid": "zpa:t:seg:101"}
    )
    assert [item["uid"] for item in response.json()["items"]] == ["zpa:t:seg:101"]


@pytest.mark.parametrize("kind", ["identity,device", "segment,service", "Identity"])
async def test_a_mixed_or_unknown_kind_is_rejected_before_any_read(client, graph, kind):
    await login(client, "vera")
    response = await client.get("/api/assessment-options", params={"snapshot": "300", "kind": kind})
    assert response.status_code == 422
    assert graph == []


def test_the_generator_search_of_identity_groups_reads_its_own_query(monkeypatch):
    reads = []

    @contextmanager
    def session(_settings, **_kwargs):
        yield object()

    def search_options(*args, **kwargs):
        raise AssertionError("the generator reads identity groups with its own query")

    def read(session, query, **params):
        reads.append((session.cts, query, params))
        return [{"uid": "zpa:t:idp:okta-finance", "name": "Finance", "address": None}]

    monkeypatch.setattr(generator_tools.dbmod, "session", session)
    monkeypatch.setattr(generator_tools.discovery, "search_options", search_options)
    monkeypatch.setattr(path, "_read", read)
    ctx = ToolContext(settings=None, snapshot=snapshotmod.Snapshot(300, None))

    result = generator_tools.search_objects(ctx, {"kind": "identity", "q": "fin"})

    assert result["items"] == [
        {
            "uid": "zpa:t:idp:okta-finance",
            "label": "IdentityGroup",
            "kind": "identity",
            "name": "Finance",
            "address": None,
        }
    ]
    assert reads == [(300, generator_tools._search_query("IdentityGroup"), {"q": "fin", "limit": 21})]
