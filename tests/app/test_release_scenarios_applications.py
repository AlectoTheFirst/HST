"""Release scenarios for the Business Application catalog: First application,
Partial application and Import update/conflict, through the API."""

from __future__ import annotations

import copy

import pytest
import yaml
from tests.app.conftest import login
from tests.app.release_scenarios_rig import (
    API_INTERFACE,
    CHECKOUT_CONNECTIONS,
    CHECKOUT_ID,
    CHECKOUT_YAML,
    Inventory,
    ScenarioStore,
    api_interface,
    commit_yaml,
    install,
)


@pytest.fixture
def store():
    return ScenarioStore()


async def test_first_application_imports_checkout_with_only_its_explicit_connections(
    client, store, monkeypatch
):
    """First application: import Checkout with clients/frontend/API/database
    groups and explicit connections; no implicit edges appear."""
    install(monkeypatch, Inventory("4000", {"4000": api_interface("10.20.0.10")}))
    await login(client, "otto")

    committed = await commit_yaml(client, CHECKOUT_YAML)
    assert committed.status_code == 201, committed.text
    stored = (await client.get(f"/api/business-applications/{CHECKOUT_ID}")).json()["application"]
    assert [group["id"] for group in stored["definition"]["groups"]] == [
        "branch-clients",
        "frontend",
        "api",
        "database",
    ]

    resolved = await client.post(
        f"/api/business-applications/{CHECKOUT_ID}/resolve", json={"snapshot": "4000"}
    )
    assert resolved.status_code == 200, resolved.text
    resolution = resolved.json()
    assert resolution["ready"] is True, resolution["issues"]
    # exactly the three authored connections, each between its authored groups
    assert {item["id"] for item in resolution["connections"]} == set(CHECKOUT_CONNECTIONS)
    assert len(resolution["connections"]) == 3
    by_id = {item["id"]: item for item in resolution["connections"]}
    assert by_id["clients-to-frontend"]["request"]["sources"] == ["192.0.2.0/24", "2001:db8:10::/64"]
    assert by_id["clients-to-frontend"]["request"]["destination"] == "Frontend"
    assert by_id["frontend-to-api"]["request"]["sources"] == ["198.51.100.10"]
    assert by_id["frontend-to-api"]["request"]["members"][0]["addresses"] == ["10.20.0.10"]
    assert by_id["api-to-database"]["request"]["sources"] == ["10.20.0.10"]
    assert by_id["api-to-database"]["request"]["destination"] == "Checkout database"
    assert {item["service_id"] for item in resolution["connections"]} == {"checkout-frontend"}

    graph = await client.get(f"/api/business-applications/{CHECKOUT_ID}/graph", params={"snapshot": "4000"})
    assert graph.status_code == 200, graph.text
    body = graph.json()
    connections = [node for node in body["nodes"] if "ApplicationConnection" in node["labels"]]
    assert sorted(node["id"] for node in connections) == sorted(
        f"conn:{item}" for item in CHECKOUT_CONNECTIONS
    )
    # each connection node links only its authored source and destination group
    endpoints = {rel["start"]: set() for rel in body["relationships"] if rel["type"] in {"FROM", "TO"}}
    for rel in body["relationships"]:
        if rel["type"] in {"FROM", "TO"}:
            endpoints[rel["start"]].add((rel["type"], rel["end"]))
    assert endpoints == {
        f"conn:{item}": {("FROM", f"group:{source}"), ("TO", f"group:{destination}")}
        for item, (source, destination) in CHECKOUT_CONNECTIONS.items()
    }
    # no relationship joins two groups, or a group to a connection, other than
    # the authored FROM/TO of a connection node
    groups = {node["id"] for node in body["nodes"] if "ComponentGroup" in node["labels"]}
    assert len(groups) == 4
    assert not [
        rel
        for rel in body["relationships"]
        if rel["start"] in groups and (rel["end"] in groups or rel["end"].startswith("conn:"))
    ]
    assert not [
        rel
        for rel in body["relationships"]
        if rel["start"].startswith("conn:") and rel["type"] not in {"FROM", "TO"}
    ]


async def test_partial_application_saves_a_draft_explains_the_gap_and_starts_no_analysis(
    client, store, monkeypatch
):
    """Partial application: a missing inventory reference saves as a draft;
    readiness explains the gap; no automatic analysis starts."""
    # snapshot 4000 holds no object for interface:api-primary
    install(monkeypatch, Inventory("4000", {"4000": {}}))
    await login(client, "otto")

    validation = await client.post(
        "/api/business-applications/validate",
        json={"yaml": CHECKOUT_YAML, "snapshot": "4000", "record": True},
    )
    assert validation.status_code == 200, validation.text
    assert validation.json()["resolution"]["ready"] is False
    digest = validation.json()["validation_digest"]
    assert isinstance(digest, str)

    committed = await commit_yaml(client, CHECKOUT_YAML, validation_digest=digest)
    assert committed.status_code == 201, committed.text
    saved = committed.json()
    assert saved["revision"] == 1
    assert saved["resolution_error"] is None
    stored = (await client.get(f"/api/business-applications/{CHECKOUT_ID}")).json()["application"]
    assert stored["definition"]["state"] == "draft"

    # readiness: the resolution saved with the commit names the gap
    resolution = await store.get_application_resolution(saved["resolution_digest"])
    assert resolution["ready"] is False
    missing = [issue for issue in resolution["issues"] if issue["code"] == "inventory-not-found"]
    assert missing == [
        {
            "code": "inventory-not-found",
            "path": "groups.api.members.api-primary",
            "detail": f"{API_INTERFACE} was not found at snapshot 4000",
            "severity": "error",
        }
    ]
    readiness = {item["id"]: item["readiness"] for item in resolution["connections"]}
    assert readiness == {
        "clients-to-frontend": "ready",
        "frontend-to-api": "unresolved",
        "api-to-database": "unresolved",
    }

    # no automatic analysis: no session, assessment or run was created
    assert await store.list_analysis_sessions() == []
    assert await store.list_assessments() == []
    assert await store.list_analysis_runs() == []
    assert (await client.get("/api/analysis-sessions")).json()["sessions"] == []


def _changed_and_removed() -> str:
    """A merge patch that changes the database port of api-to-database and
    keeps the service naming only the connections that remain."""
    document = yaml.safe_load(CHECKOUT_YAML)
    patch = {
        "schema_version": 1,
        "kind": "BusinessApplication",
        "id": CHECKOUT_ID,
        "services": [
            {
                "id": "checkout-frontend",
                "name": "Checkout frontend",
                "connection_ids": ["frontend-to-api", "api-to-database"],
            }
        ],
        "connections": [
            {
                **next(item for item in document["connections"] if item["id"] == "api-to-database"),
                "destination_ports": [5433],
            }
        ],
    }
    return yaml.safe_dump(patch, sort_keys=False)


async def _history(store) -> list[tuple[int, str, dict]]:
    return [
        (item.revision, item.digest, copy.deepcopy(item.definition))
        for item in await store.list_application_revisions(CHECKOUT_ID, 100)
    ]


async def test_import_preview_shows_a_changed_connection_beside_an_explicit_removal(
    client, store, monkeypatch
):
    """Import update/conflict, preview half: one changed connection and one
    explicit removal are both previewed, and the preview writes nothing."""
    install(monkeypatch, Inventory("4000", {"4000": api_interface("10.20.0.10")}))
    await login(client, "otto")
    assert (await commit_yaml(client, CHECKOUT_YAML)).status_code == 201
    before = await _history(store)

    removals = {"connections": ["clients-to-frontend"]}
    preview = await client.post(
        "/api/business-applications/import/preview",
        json={"yaml": _changed_and_removed(), "removals": removals},
    )
    assert preview.status_code == 200, preview.text
    changes = preview.json()["changes"]
    assert changes["connections_updated"] == ["api-to-database"]
    assert changes["connections_removed"] == ["clients-to-frontend"]
    assert changes["connections_unchanged"] == ["frontend-to-api"]
    assert changes["connections_created"] == []
    assert preview.json()["no_op"] is False
    assert await _history(store) == before


async def test_import_commit_after_a_concurrent_revision_conflicts_without_a_partial_write(
    client, store, monkeypatch
):
    """Import update/conflict, conflict half: a revision saved by the editor
    after the preview makes the commit answer 409, and nothing of the import
    is written."""
    install(monkeypatch, Inventory("4000", {"4000": api_interface("10.20.0.10")}))
    await login(client, "otto")
    assert (await commit_yaml(client, CHECKOUT_YAML)).status_code == 201

    text = _changed_and_removed()
    removals = {"connections": ["clients-to-frontend"]}
    preview = (
        await client.post(
            "/api/business-applications/import/preview", json={"yaml": text, "removals": removals}
        )
    ).json()
    token = {key: preview[key] for key in ("base_revision", "base_digest", "preview_digest")}

    # a concurrent UI revision renames the application
    current = (await client.get(f"/api/business-applications/{CHECKOUT_ID}")).json()["application"]
    edited = await client.put(
        f"/api/business-applications/{CHECKOUT_ID}",
        json={
            "definition": {**current["definition"], "name": "Checkout (edited)"},
            "expected_revision": 1,
            "source": "editor",
        },
    )
    assert edited.status_code == 200, edited.text
    assert edited.json()["revision"] == 2
    before = await _history(store)
    sessions_before = await store.list_analysis_sessions()

    stale = await client.post(
        "/api/business-applications/import/commit",
        json={"yaml": text, "removals": removals, **token},
    )
    assert stale.status_code == 409, stale.text

    after = await _history(store)
    assert after == before
    assert [revision for revision, _, _ in after] == [2, 1]
    newest = after[0][2]
    assert newest["name"] == "Checkout (edited)"
    assert {item["id"] for item in newest["connections"]} == set(CHECKOUT_CONNECTIONS)
    database = next(item for item in newest["connections"] if item["id"] == "api-to-database")
    assert database["destination_ports"] == [5432]
    assert await store.list_analysis_sessions() == sessions_before
