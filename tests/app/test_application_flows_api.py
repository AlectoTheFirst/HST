"""GET /api/business-applications/{id}/flows and .../graph: read only,
pinned to the requested run, and built from stored evaluations only."""

from __future__ import annotations

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

from hst.app.routes import business_applications as routes
from hst.applications.models import BusinessApplicationDefinition
from hst.applications.resolution import (
    AddressBinding,
    InventoryCandidate,
    StaticInventoryReader,
    resolve_application,
)
from hst.applications.service import save_definition
from hst.assessment import service as assessment_service
from hst.assessment.store import AnalysisRun, MemoryAssessmentStore
from hst.results.project import condition_result

REFERENCES = {
    value: {
        "snapshot": value,
        "manifest_sha256": value[0] * 64,
        "estate": "test",
        "observation_floor_ms": None,
    }
    for value in ("4000", "3900")
}

DEFINITION = {
    "id": "shop",
    "name": "Shop",
    "groups": [
        {"id": "clients", "name": "Clients", "members": [{"id": "lan", "address": "10.9.0.0/24"}]},
        {
            "id": "servers",
            "name": "Servers",
            "members": [{"id": "db", "inventory": {"kind": "ip", "uid": "ip:10.0.0.5"}}],
        },
    ],
    "connections": [
        {
            "id": "web",
            "name": "Web",
            "source": "clients",
            "destination": "servers",
            "protocol": "tcp",
            "destination_ports": [443],
            "destination_condition": {"kind": "member", "member": "db"},
        },
        {
            "id": "admin",
            "name": "Admin",
            "source": "clients",
            "destination": "servers",
            "protocol": "tcp",
            "destination_ports": [22],
            "destination_condition": {"kind": "member", "member": "db"},
        },
    ],
    "services": [{"id": "front", "name": "Front", "connection_ids": ["web", "admin"]}],
}

ROWS = [
    {
        "uid": "ip:10.0.0.5",
        "labels": ["Obj", "IpAddress"],
        "props": {"uid": "ip:10.0.0.5", "ip": "10.0.0.5"},
        "outgoing": [{"type": "IN", "uid": "pfx:10.0.0.0/24", "labels": ["Obj", "Prefix"], "props": {}}],
        "incoming": [],
        "anchors": [
            {
                "address": "ip:10.0.0.5",
                "interface": "dev-db/if/eth0",
                "interface_props": {"name": "eth0"},
                "uid": "dev-db",
                "labels": ["Obj", "Device"],
                "props": {"hostname": "db"},
            }
        ],
    }
]


class ApplicationFakeStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return ApplicationFakeStore()


@pytest.fixture
def graph(monkeypatch):
    """Pins every requested snapshot and resolves against a fixed inventory.
    Records what each read was pinned to."""
    calls: dict[str, list] = {"pinned": [], "resolved": []}

    def snapshot_reference(settings, value):
        calls["pinned"].append(value)
        return REFERENCES[value]

    def resolved_inventory(settings, definition, revision, reference, connections):
        calls["resolved"].append((reference["snapshot"], revision, list(connections)))
        reader = StaticInventoryReader(
            {
                "ip:10.0.0.5": [
                    InventoryCandidate(
                        "ip:10.0.0.5", "ip", (AddressBinding("10.0.0.5", None, "ip:10.0.0.5"),)
                    )
                ]
            }
        )
        resolution = resolve_application(
            BusinessApplicationDefinition.model_validate(definition),
            revision=revision,
            snapshot=reference,
            reader=reader,
            connection_ids=connections,
        )
        return resolution, ROWS

    monkeypatch.setattr(assessment_service, "snapshot_reference", snapshot_reference)
    monkeypatch.setattr(routes, "_resolved_inventory", resolved_inventory)
    return calls


async def _application(store, revisions=1):
    saved = None
    for index in range(revisions):
        body = {**DEFINITION, "description": f"revision {index + 1}"}
        saved = await save_definition(
            store,
            BusinessApplicationDefinition.model_validate(body),
            expected_revision=index,
            actor=1,
        )
    return saved


async def _evaluated(
    store, *, snapshot, revision, connection="web", state="completed", outcome="holds", stored_outcome=None
):
    """A stored connection session with one run of `connection`, as an
    Analysis run from the application's Coverage saves it. `stored_outcome`
    gives the run summary an `outcome` and no result."""
    session_id = f"session-{snapshot}-{revision}-{connection}"
    run_id = f"run-{snapshot}-{revision}-{connection}"
    selection = {
        "id": connection,
        "name": connection,
        "source": {
            "kind": "application_connection",
            "reference": {
                "application": {"id": "shop", "revision": revision},
                "service_id": "front",
                "connection_id": connection,
            },
            "request": {},
            "resolved_scope_digest": "e" * 64,
        },
    }
    definition = {
        "id": session_id,
        "revision": 2,
        "input": {
            "kind": "connection",
            "snapshot": {key: REFERENCES[snapshot][key] for key in ("snapshot", "manifest_sha256", "estate")},
            "connections": [selection],
            "changes": [],
        },
        "runs": [{"id": run_id, "item_id": connection, "execution": state, "coverage": "not_started"}],
    }
    if stored_outcome is not None:
        definition["runs"][0].update(outcome=stored_outcome, result=None)
    await store.create_analysis_session(
        title="Shop analysis", definition=definition, results={}, created_by=1, session_id=session_id
    )
    evidence = [
        {
            "side": "before",
            "member": "db",
            # the stored run records the engine's outcome as its result
            "result": condition_result(outcome).model_dump(mode="json"),
            "steps": [
                {"device_uid": "dev-edge", "stage": "entry", "kind": "attach", "detail": "", "unknown": []},
                {"device_uid": "dev-fw", "stage": "filter", "kind": "permit", "detail": "", "unknown": []},
                {"device_uid": "dev-db", "stage": "next-hop", "kind": "arrive", "detail": "", "unknown": []},
            ],
            "missing": [],
        }
    ]
    run = AnalysisRun(
        id=run_id,
        assessment_id=session_id,
        assessment_revision=1,
        kind="evaluate",
        inputs={},
        input_digest="f" * 64,
        snapshot_refs=[REFERENCES[snapshot]],
        engine_version="test",
        created_by=1,
        created_at=f"2026-10-16T00:00:0{len(store._assessment_records) % 10}",
        state=state,
        result={"evidence": {"count": 1, "items": evidence, "truncated": False}}
        if state == "completed"
        else None,
    )
    async with store.assessment_transaction() as tx:
        await tx.put("run", {**run.as_dict(), "revision": 1})


async def test_both_reads_need_a_login_and_a_viewer_may_read(client, store, graph):
    await _application(store)
    assert (await client.get("/api/business-applications/shop/flows?snapshot=4000")).status_code == 401
    assert (await client.get("/api/business-applications/shop/graph?snapshot=4000")).status_code == 401
    await login(client, "vera")
    assert (await client.get("/api/business-applications/shop/flows?snapshot=4000")).status_code == 200
    assert (await client.get("/api/business-applications/shop/graph?snapshot=4000")).status_code == 200
    assert (await client.get("/api/business-applications/missing/flows?snapshot=4000")).status_code == 404
    assert (await client.get("/api/business-applications/shop/flows")).status_code == 422


async def test_flows_are_pinned_to_the_requested_run_and_never_evaluate(client, store, graph):
    await _application(store)
    await _evaluated(store, snapshot="4000", revision=1)
    await login(client, "vera")
    before = {key for key in store._assessment_records if key[0] == "run"}

    response = await client.get("/api/business-applications/shop/flows?snapshot=4000")

    assert response.status_code == 200, response.text
    body = response.json()
    assert graph["pinned"] == ["4000"]
    assert graph["resolved"] == [("4000", 1, [])]
    assert body["snapshot"]["snapshot"] == "4000"
    web, admin = body["connections"]
    assert (web["id"], web["result"]["answer"], admin["id"], admin["state"]) == (
        "web",
        "true",
        "admin",
        "not-evaluated",
    )
    assert web["paths"][0]["devices"] == ["dev-edge", "dev-fw", "dev-db"]
    assert web["endpoints"]["destination"][0]["devices"] == ["dev-db"]
    assert web["evaluation"]["stale"] == {"snapshot": False, "revision": False}
    assert body["stale"] == {"snapshot": False, "revision": False}
    # the read queued nothing
    assert {key for key in store._assessment_records if key[0] == "run"} == before


async def test_an_evaluation_of_another_run_or_revision_carries_the_banner_data(client, store, graph):
    await _application(store, revisions=2)
    await _evaluated(store, snapshot="3900", revision=1, outcome="does-not-hold")
    await login(client, "vera")

    latest = (await client.get("/api/business-applications/shop/flows?snapshot=4000")).json()
    web = latest["connections"][0]
    assert web["result"]["answer"] == "false"
    assert web["evaluation"]["snapshot"] == "3900"
    assert web["evaluation"]["stale"] == {"snapshot": True, "revision": True}
    assert latest["stale"] == {"snapshot": True, "revision": True}
    assert latest["evaluated"] == {"snapshots": ["3900"], "revisions": [1]}

    pinned = (
        await client.get("/api/business-applications/shop/flows?snapshot=3900&revision=1&connection_id=web")
    ).json()
    assert graph["resolved"][-1] == ("3900", 1, ["web"])
    assert [item["id"] for item in pinned["connections"]] == ["web"]
    assert pinned["application"]["revision"] == 1
    assert pinned["stale"] == {"snapshot": False, "revision": False}


async def test_an_evaluation_at_the_map_run_wins_over_a_newer_one_elsewhere(client, store, graph):
    await _application(store)
    await _evaluated(store, snapshot="4000", revision=1)
    await _evaluated(store, snapshot="3900", revision=1, outcome="does-not-hold")
    await login(client, "vera")

    web = (await client.get("/api/business-applications/shop/flows?snapshot=4000")).json()["connections"][0]

    assert web["evaluation"]["snapshot"] == "4000"
    assert web["result"]["answer"] == "true"


async def test_a_run_stored_with_an_outcome_is_not_shown(client, store, graph):
    await _application(store)
    await _evaluated(store, snapshot="4000", revision=1, stored_outcome="holds")
    await login(client, "vera")

    web = (await client.get("/api/business-applications/shop/flows?snapshot=4000")).json()["connections"][0]

    assert web["evaluation"] is None and web["state"] == "not-evaluated"


async def test_an_unknown_connection_is_refused(client, store, graph):
    await _application(store)
    await login(client, "vera")
    response = await client.get("/api/business-applications/shop/flows?snapshot=4000&connection_id=nope")
    assert response.status_code == 422


async def test_the_graph_joins_the_definition_to_the_inventory_at_the_run(client, store, graph):
    await _application(store)
    await login(client, "vera")

    response = await client.get("/api/business-applications/shop/graph?snapshot=4000")

    assert response.status_code == 200, response.text
    body = response.json()
    assert graph["pinned"] == ["4000"]
    nodes = {node["id"]: node for node in body["nodes"]}
    assert {"app:shop", "service:front", "group:clients", "group:servers", "conn:web", "conn:admin"} <= set(
        nodes
    )
    assert nodes["ip:10.0.0.5"]["labels"][0] == "IpAddress"
    assert nodes["dev-db"]["labels"][0] == "Device"
    assert nodes["member:clients/lan"]["properties"]["address"] == "10.9.0.0/24"
    edges = {(rel["start"], rel["type"], rel["end"]) for rel in body["relationships"]}
    assert ("group:servers", "MEMBER", "ip:10.0.0.5") in edges
    assert ("conn:web", "FROM", "group:clients") in edges
    assert ("conn:web", "TO", "group:servers") in edges
    assert ("service:front", "ASSOCIATES", "conn:web") in edges
    assert ("dev-db/if/eth0", "HAS_IP", "ip:10.0.0.5") in edges
    assert ("dev-db/if/eth0", "ON", "dev-db") in edges
    assert ("ip:10.0.0.5", "IN", "pfx:10.0.0.0/24") in edges
    assert body["truncated"] is False
    assert body["library_query"] == {"key": "application-inventory", "params": {"uids": "ip:10.0.0.5"}}
