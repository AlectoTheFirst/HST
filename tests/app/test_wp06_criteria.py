"""WP-06 "Done when" criterion of the Business Applications plan: the selected
protections of a simulation session reach its queued run, and a protection
that cannot be evaluated refuses the run."""

from __future__ import annotations

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

from hst.app.routes import analysis_sessions
from hst.assessment.store import MemoryAssessmentStore

SNAPSHOT = {"snapshot": "100", "manifest_sha256": "abc", "estate": "test", "observation_floor_ms": None}
APPLICATION_DIGEST = "a" * 64
SCOPE_DIGEST = "b" * 64


def _request(name: str, address: str) -> dict:
    return {
        "name": name,
        "destination": name,
        "sources": ["10.0.0.1"],
        "members": [{"name": "api", "addresses": [address]}],
        "condition": {"kind": "member", "member": "api"},
        "success": "forward",
    }


class SessionFakeStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return SessionFakeStore()


@pytest.fixture(autouse=True)
def pinned(monkeypatch):
    monkeypatch.setattr(analysis_sessions, "_pin", lambda settings, stated: stated.model_dump(mode="json"))


async def _application(store, readiness: str) -> None:
    await store.create_application_revision(
        definition={
            "schema_version": 1,
            "kind": "BusinessApplication",
            "id": "checkout",
            "name": "Checkout",
            "state": "ready",
            "services": [
                {"id": "api-service", "name": "API", "connection_ids": ["client-api"], "component_roles": []}
            ],
            "groups": [],
            "connections": [],
        },
        digest=APPLICATION_DIGEST,
        created_by=1,
        expected_revision=0,
    )
    await store.save_application_resolution(
        {
            "digest": SCOPE_DIGEST,
            "application": {"id": "checkout", "revision": 1, "digest": APPLICATION_DIGEST},
            "snapshot": SNAPSHOT,
            "connections": [
                {
                    "id": "client-api",
                    "service_id": "api-service",
                    "readiness": readiness,
                    "request": _request("Client to API", "192.0.2.10"),
                    "issues": [],
                }
            ],
        }
    )


def _inline(name: str, address: str, desired: str) -> dict:
    return {"kind": "inline", "name": name, "request": _request(name, address), "desired": desired}


APPLICATION_PROTECTION = {
    "kind": "application_connection",
    "reference": {
        "application": {"id": "checkout", "revision": 1, "digest": APPLICATION_DIGEST},
        "service_id": "api-service",
        "connection_id": "client-api",
    },
    "resolved_scope_digest": SCOPE_DIGEST,
    "desired": "holds",
}


async def _create(client, protected: list[dict]) -> dict:
    created = await client.post(
        "/api/analysis-sessions",
        json={
            "title": "Protected change",
            "input": {
                "kind": "simulation",
                "snapshot": SNAPSHOT,
                "changes": [{"kind": "route.add", "params": {"prefix": "192.0.2.0/24"}}],
                "scope": {"flows": [], "sites": []},
                "bounds": {"max_flows": 50, "max_seconds": 30},
                "protected": protected,
            },
        },
    )
    assert created.status_code == 201, created.text
    return created.json()


async def _execute(client, created: dict):
    return await client.post(
        f"/api/analysis-sessions/{created['id']}/runs",
        json={"session_revision": created["revision"], "input_digest": created["input_digest"]},
    )


async def test_a_simulation_run_holds_one_protected_request_per_selected_protection_in_order(client, store):
    await _application(store, "ready")
    await login(client, "otto")
    protected = [
        _inline("Admin", "192.0.2.20", "isolated"),
        APPLICATION_PROTECTION,
        _inline("Backup", "192.0.2.30", "holds"),
    ]
    created = await _create(client, protected)
    assert [item["kind"] for item in created["definition"]["input"]["protected"]] == [
        "inline",
        "application_connection",
        "inline",
    ]

    executed = await _execute(client, created)

    assert executed.status_code == 202, executed.text
    assert executed.json()["definition"]["input"]["protected"] == created["definition"]["input"]["protected"]
    run = await store.claim_analysis("wp06-test")
    assert run is not None and run.id == executed.json()["definition"]["runs"][0]["id"]
    assert (
        run.inputs["analysis_session_simulation"]["protected"] == created["definition"]["input"]["protected"]
    )
    requests = run.inputs["protected_requests"]
    assert [item["members"][0]["addresses"] for item in requests] == [
        ["192.0.2.20"],
        ["192.0.2.10"],
        ["192.0.2.30"],
    ]
    assert requests[1]["name"] == "Client to API"


async def test_a_simulation_with_an_unresolved_protected_connection_is_refused_and_queues_no_run(
    client, store
):
    await _application(store, "unresolved")
    await login(client, "otto")
    created = await _create(client, [_inline("Admin", "192.0.2.20", "holds"), APPLICATION_PROTECTION])

    executed = await _execute(client, created)

    assert executed.status_code == 422
    assert "a protected application connection is unresolved" in executed.json()["error"]
    assert await store.claim_analysis("wp06-test") is None
    read = (await client.get(f"/api/analysis-sessions/{created['id']}")).json()
    assert read["revision"] == 1
    assert read["definition"]["runs"] == []
