"""Release scenario Service identity, standalone half: a standalone requirement
saved through POST /api/requirements runs in an Analysis session without being
presented as a service."""

from __future__ import annotations

import json

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

from hst.assessment import service as assessment_service
from hst.assessment.store import MemoryAssessmentStore

SNAPSHOT = {
    "snapshot": "4000",
    "manifest_sha256": "manifest-4000",
    "estate": "synthetic",
    "observation_floor_ms": None,
}
STANDALONE_REQUEST = {
    "name": "Branch to payroll",
    "destination": "Payroll",
    "sources": ["192.0.2.10"],
    "members": [{"name": "payroll", "addresses": ["198.51.100.40"]}],
    "condition": {"kind": "member", "member": "payroll"},
    "proto": "tcp",
    "port": "443",
    "success": "forward",
}


class RequirementStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return RequirementStore()


@pytest.fixture(autouse=True)
def pinned(monkeypatch):
    monkeypatch.setattr(assessment_service, "snapshot_reference", lambda settings, value=None: dict(SNAPSHOT))
    monkeypatch.setattr(assessment_service, "engine_version", lambda settings: "engine-release-test")


async def test_an_old_standalone_requirement_runs_without_being_presented_as_a_service(client, store):
    await login(client, "otto")
    saved = await client.post(
        "/api/requirements",
        json={
            "title": "Branch to payroll",
            "definition": {"request": STANDALONE_REQUEST, "snapshot": "4000"},
        },
    )
    assert saved.status_code == 200, saved.text
    requirement = saved.json()

    created = await client.post(
        "/api/analysis-sessions",
        json={
            "title": "Standalone requirement",
            "input": {
                "kind": "connection",
                "snapshot": SNAPSHOT,
                "connections": [
                    {
                        "id": "payroll",
                        "name": "Branch to payroll",
                        "source": {
                            "kind": "saved_requirement",
                            "requirement": {"id": requirement["id"], "revision": requirement["revision"]},
                            "request": STANDALONE_REQUEST,
                        },
                    }
                ],
            },
        },
    )
    assert created.status_code == 201, created.text
    session = created.json()
    executed = await client.post(
        f"/api/analysis-sessions/{session['id']}/runs",
        json={"session_revision": session["revision"], "input_digest": session["input_digest"]},
    )
    assert executed.status_code == 202, executed.text
    body = executed.json()
    (connection,) = body["definition"]["input"]["connections"]
    assert connection["source"]["kind"] == "saved_requirement"
    assert connection["source"]["requirement"] == {
        "id": requirement["id"],
        "revision": requirement["revision"],
        "digest": None,
    }
    # nothing names an application or a service for it
    presented = json.dumps(body["definition"])
    assert "application" not in presented
    assert "service" not in presented
    (run,) = body["definition"]["runs"]
    assert run["item_id"] == "payroll"
    assert [item.id for item in await store.list_analysis_runs()] == [run["id"]]
