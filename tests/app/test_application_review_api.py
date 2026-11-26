"""The review flag of Business Applications and the Analysis sessions bound to an application."""

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore
from tests.app.test_application_review_store import connection_session, save_session, simulation_session

from hst.assessment.store import MemoryAssessmentStore

APPLICATION = "checkout-production"
URL = f"/api/business-applications/{APPLICATION}"
YAML = """\
schema_version: 1
kind: BusinessApplication
id: checkout-production
name: {name}
groups:
  - id: clients
    name: Clients
    members: [{{id: client, address: 192.0.2.1}}]
  - id: servers
    name: Servers
    members: [{{id: server, address: 198.51.100.10}}]
connections:
  - id: web
    name: Web
    source: clients
    destination: servers
    protocol: tcp
    destination_ports: [443]
    destination_condition: {{kind: member, member: server}}
services:
  - id: frontend
    name: Frontend
    connection_ids: [web]
"""


class ApplicationFakeStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return ApplicationFakeStore()


def definition(name: str = "Checkout") -> dict:
    return {
        "schema_version": 1,
        "id": APPLICATION,
        "name": name,
        "groups": [
            {"id": "clients", "name": "Clients", "members": [{"id": "client", "address": "192.0.2.1"}]},
            {"id": "servers", "name": "Servers", "members": [{"id": "server", "address": "198.51.100.10"}]},
        ],
        "connections": [
            {
                "id": "web",
                "name": "Web",
                "source": "clients",
                "destination": "servers",
                "protocol": "tcp",
                "destination_ports": [443],
                "destination_condition": {"kind": "member", "member": "server"},
            }
        ],
        "services": [{"id": "frontend", "name": "Frontend", "connection_ids": ["web"]}],
    }


async def create(client) -> None:
    created = await client.post("/api/business-applications", json={"definition": definition()})
    assert created.status_code == 201, created.text


async def revise(client, name: str, expected_revision: int) -> dict:
    saved = await client.put(
        URL, json={"definition": definition(name), "expected_revision": expected_revision}
    )
    assert saved.status_code == 200, saved.text
    return saved.json()


def user_id(store, username: str) -> int:
    return next(user.id for user in store.users.values() if user.username == username)


async def test_a_new_revision_opens_a_flag_when_a_session_binds_an_older_revision(client, store):
    await login(client, "otto")
    await create(client)
    await save_session(store, connection_session("bound", [(APPLICATION, 1)]))

    assert (await revise(client, "Checkout 2", 1))["revision"] == 2
    review = (await client.get(f"{URL}/review")).json()
    current = review["current"]
    assert current["application_id"] == APPLICATION
    assert (current["state"], current["reason"], current["revision"]) == ("open", "revision 2 saved", 2)
    assert (current["opened_by"], current["closed_at"], current["closed_by"]) == (None, None, None)
    assert review["history"] == [current]

    await revise(client, "Checkout 3", 2)
    assert [item["id"] for item in (await client.get(f"{URL}/review")).json()["history"]] == [current["id"]]

    [listed] = (await client.get("/api/business-applications")).json()["applications"]
    assert (listed["revision"], listed["review"], listed["analyses"], listed["connections"]) == (
        3,
        "open",
        1,
        1,
    )


async def test_no_flag_opens_without_a_session_bound_to_an_older_revision(client, store):
    await login(client, "otto")
    await create(client)
    await save_session(store, connection_session("other", [("other", 1)]))
    await revise(client, "Checkout 2", 1)
    await save_session(store, simulation_session("current", APPLICATION, 2))
    same = await client.put(URL, json={"definition": definition("Checkout 2"), "expected_revision": 2})
    assert same.status_code == 200 and same.json()["revision"] == 2

    assert (await client.get(f"{URL}/review")).json() == {"current": None, "history": []}
    [listed] = (await client.get("/api/business-applications")).json()["applications"]
    assert (listed["review"], listed["analyses"], listed["connections"]) == (None, 1, 1)


async def test_an_import_commit_opens_the_flag(client, store):
    await login(client, "otto")
    await create(client)
    await save_session(store, simulation_session("protected", APPLICATION, 1))
    body = {"yaml": YAML.format(name="Checkout imported")}
    preview = await client.post("/api/business-applications/import/preview", json=body)
    assert preview.status_code == 200, preview.text
    committed = await client.post(
        "/api/business-applications/import/commit",
        json={
            **body,
            "base_revision": preview.json()["base_revision"],
            "base_digest": preview.json()["base_digest"],
            "preview_digest": preview.json()["preview_digest"],
        },
    )
    assert committed.status_code == 201, committed.text
    assert committed.json()["revision"] == 2

    current = (await client.get(f"{URL}/review")).json()["current"]
    assert (current["reason"], current["revision"], current["opened_by"]) == ("revision 2 saved", 2, None)


async def test_analyses_lists_the_bound_sessions_with_their_bound_revisions_and_runs(client, store):
    await login(client, "otto")
    await create(client)
    await revise(client, "Checkout 2", 1)
    queued = {"id": "run-queued", "item_id": "item-0", "execution": "queued", "coverage": "not_started"}
    await save_session(
        store, connection_session("connection", [(APPLICATION, 1), (APPLICATION, 2)], [queued])
    )
    await save_session(store, connection_session("other", [("other", 1)]))
    simulation = await save_session(store, simulation_session("simulation", APPLICATION, 2))
    run = await store.enqueue_analysis(
        assessment_id="simulation",
        assessment_revision=1,
        kind="simulation",
        inputs={},
        snapshot_refs=[{"snapshot": "100"}],
        engine_version="test",
        created_by=None,
    )
    await store.cancel_analysis(run.id)
    summary = {"id": run.id, "item_id": "simulation", "execution": "queued", "coverage": "not_started"}
    await store.create_analysis_session(
        title="simulation",
        definition={**simulation_session("simulation", APPLICATION, 2), "revision": 2, "runs": [summary]},
        results={},
        created_by=None,
        session_id="simulation",
        expected_revision=simulation.revision,
    )

    answer = await client.get(f"{URL}/analyses")
    assert answer.status_code == 200, answer.text
    assert answer.json() == {
        "analyses": [
            {
                "session_id": "simulation",
                "title": "simulation",
                "kind": "simulation",
                "session_revision": 2,
                "bound_revisions": [2],
                "current_revision": 2,
                "stale": False,
                "runs": [{"id": run.id, "execution": "cancelled"}],
            },
            {
                "session_id": "connection",
                "title": "connection",
                "kind": "connection",
                "session_revision": 1,
                "bound_revisions": [1, 2],
                "current_revision": 2,
                "stale": True,
                "runs": [{"id": "run-queued", "execution": "queued"}],
            },
        ]
    }
    assert (await client.get("/api/business-applications/missing/analyses")).status_code == 404


async def test_a_flag_opened_by_hand_is_closed_by_mark_reviewed(client, store):
    await login(client, "otto")
    await create(client)
    otto = user_id(store, "otto")

    assert (await client.post(f"{URL}/review", json={"reason": ""})).status_code == 422
    assert (await client.post(f"{URL}/review/close")).status_code == 409
    opened = await client.post(f"{URL}/review", json={"reason": "owner changed"})
    assert opened.status_code == 201, opened.text
    flag = opened.json()
    assert (flag["state"], flag["reason"], flag["revision"], flag["opened_by"]) == (
        "open",
        "owner changed",
        1,
        otto,
    )
    assert (await client.post(f"{URL}/review", json={"reason": "again"})).status_code == 409

    closed = await client.post(f"{URL}/review/close")
    assert closed.status_code == 200, closed.text
    assert (closed.json()["id"], closed.json()["state"], closed.json()["closed_by"]) == (
        flag["id"],
        "closed",
        otto,
    )
    assert closed.json()["closed_at"] is not None
    assert (await client.post(f"{URL}/review/close")).status_code == 409
    missing = "/api/business-applications/missing/review"
    assert (await client.post(missing, json={"reason": "x"})).status_code == 404
    assert (await client.post(f"{missing}/close")).status_code == 404

    await login(client, "vera")
    assert (await client.post(f"{URL}/review", json={"reason": "viewer"})).status_code == 403
    review = await client.get(f"{URL}/review")
    assert review.status_code == 200
    assert review.json() == {"current": None, "history": [closed.json()]}
    assert (await client.get(missing)).status_code == 404
