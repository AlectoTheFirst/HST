import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

from hst.app.routes import analysis_sessions
from hst.assessment import service as assessment_service
from hst.assessment.store import MemoryAssessmentStore
from hst.results.project import condition_result


class SessionFakeStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return SessionFakeStore()


@pytest.fixture(autouse=True)
def pinned(monkeypatch):
    monkeypatch.setattr(
        analysis_sessions,
        "_pin",
        lambda settings, stated: stated.model_dump(mode="json"),
    )


def simulation_input():
    return {
        "kind": "simulation",
        "snapshot": {"snapshot": "100", "manifest_sha256": "abc", "estate": "test"},
        "changes": [
            {"kind": "route.remove", "params": {"prefix": "192.0.2.0/24"}},
            {"kind": "route.add", "params": {"prefix": "192.0.2.0/24"}},
        ],
        "scope": {
            "flows": [{"src": "10.0.0.1", "dst": "192.0.2.1", "proto": "tcp", "port": 443}],
            "sites": [],
        },
        "bounds": {"max_flows": 50, "max_seconds": 30},
        "protected": [],
    }


async def test_service_free_simulation_is_saved_and_exported_without_rerun(client, store, monkeypatch):
    await login(client, "otto")
    calls = []

    def simulate(settings, value, source_kinds, requests):
        calls.append([change.kind for change in value.changes])
        return {
            "snapshot": value.snapshot.model_dump(mode="json"),
            "simulation": {"baseline": {"routes": ["old"]}, "predicted": {"routes": ["new"]}},
            "protected": [],
        }

    monkeypatch.setattr(analysis_sessions, "_simulate", simulate)
    created = await client.post(
        "/api/analysis-sessions", json={"title": "Route change", "input": simulation_input()}
    )
    assert created.status_code == 201, created.text
    identifier = created.json()["id"]
    fenced = await client.post(
        f"/api/analysis-sessions/{identifier}/runs",
        json={"session_revision": 1, "input_digest": "0" * 64},
    )
    assert fenced.status_code == 409
    executed = await client.post(
        f"/api/analysis-sessions/{identifier}/runs",
        json={"session_revision": 1, "input_digest": created.json()["input_digest"]},
    )
    assert executed.status_code == 202, executed.text
    assert executed.json()["revision"] == 2
    assert executed.json()["definition"]["runs"][0]["execution"] == "queued"
    claimed = await store.claim_analysis("simulation-test")
    assert claimed is not None and claimed.lease_token
    claimed_response = await client.get(f"/api/analysis-sessions/{identifier}/runs/{claimed.id}")
    assert claimed_response.status_code == 200
    assert "lease_token" not in claimed_response.json()["run"]
    assert "claimed_by" not in claimed_response.json()["run"]
    assert "checkpoint" not in claimed_response.json()["run"]
    result = assessment_service.execute(None, claimed.inputs)
    assert await store.finish_analysis(claimed.id, claimed.lease_token, result=result)
    assert calls == [["route.remove", "route.add"]]
    run_id = executed.json()["definition"]["runs"][0]["id"]
    run = await client.get(f"/api/analysis-sessions/{identifier}/runs/{run_id}")
    assert run.status_code == 200
    assert run.json()["run"]["input_digest"] == claimed.input_digest
    assert run.json()["run"]["result"]["simulation"]["predicted"] == {"routes": ["new"]}
    run_export = await client.get(f"/api/analysis-sessions/{identifier}/runs/{run_id}/export")
    assert run_export.status_code == 200
    assert run_export.headers["x-hst-export-mode"] == "exact-saved-run"
    assert calls == [["route.remove", "route.add"]]
    exported = await client.get(f"/api/analysis-sessions/{identifier}/export?revision=2")
    assert exported.status_code == 200
    assert exported.headers["x-hst-export-mode"] == "exact-saved-run"
    assert exported.json()["results"]["simulation"]["predicted"] == {"routes": ["new"]}
    assert calls == [["route.remove", "route.add"]]


def test_session_summary_reads_nested_verdict_and_bounded_coverage():
    fails = condition_result("does-not-hold").model_dump(mode="json")
    passes = condition_result("holds").model_dump(mode="json")
    assert analysis_sessions._result({"outcomes": {"after": {"result": fails}}})["answer"] == "false"
    assert analysis_sessions._result({"outcomes": {"after": {"result": passes}}})["answer"] == "true"
    assert analysis_sessions._coverage({"search_complete": False}) == "partial"
    assert analysis_sessions._coverage({"scoped_search_complete": False}) == "partial"


BATCH_REQUEST = {
    "name": "Batch item",
    "destination": "API",
    "sources": ["10.0.0.1"],
    "members": [{"name": "api", "addresses": ["192.0.2.1"]}],
    "condition": {"kind": "member", "member": "api"},
    "success": "forward",
}


async def _batch_session(client, count: int) -> dict:
    connections = [
        {
            "id": f"item-{index}",
            "name": f"Item {index}",
            "source": {"kind": "inline", "request": BATCH_REQUEST},
        }
        for index in range(count)
    ]
    response = await client.post(
        "/api/analysis-sessions",
        json={
            "title": "Batch",
            "input": {
                "kind": "connection",
                "snapshot": {"snapshot": "100", "manifest_sha256": "abc", "estate": "test"},
                "connections": connections,
            },
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _queued_runs(monkeypatch, store) -> list[str]:
    """Submissions return queued runs the store reports as queued."""
    submitted: list[str] = []
    runs: dict[str, SimpleNamespace] = {}

    async def submit(_store, _settings, assessment, _body, _actor):
        run = SimpleNamespace(id=f"run-{len(submitted)}", state="queued", input_digest="d", result=None)
        submitted.append(assessment.title)
        runs[run.id] = run
        return run

    async def get_run(run_id):
        return runs.get(run_id)

    monkeypatch.setattr(analysis_sessions.assessment_routes, "_definition", lambda *_: {})
    monkeypatch.setattr(analysis_sessions.assessment_routes, "submit", submit)
    monkeypatch.setattr(store, "get_analysis_run", get_run)
    return submitted


async def test_a_session_run_answers_503_and_queues_no_run_while_the_cycle_lock_stays_held(
    client, store, monkeypatch
):
    monkeypatch.setattr(analysis_sessions.assessment_routes, "CYCLE_LOCK_WAIT_S", 0.01)
    await login(client, "otto")
    created = await client.post(
        "/api/analysis-sessions", json={"title": "Route change", "input": simulation_input()}
    )
    async with store.cycle_lock():
        response = await client.post(
            f"/api/analysis-sessions/{created.json()['id']}/runs",
            json={"session_revision": 1, "input_digest": created.json()["input_digest"]},
        )
    assert response.status_code == 503
    assert response.json()["error"] == analysis_sessions.assessment_routes.CYCLE_LOCK_BUSY
    assert await store.claim_analysis("worker") is None


async def test_connections_past_the_admission_bound_are_omitted_as_partial(client, store, monkeypatch):
    await login(client, "otto")
    created = await _batch_session(client, 9)
    submitted = _queued_runs(monkeypatch, store)
    response = await client.post(
        f"/api/analysis-sessions/{created['id']}/runs",
        json={"session_revision": 1, "input_digest": created["input_digest"]},
    )
    assert response.status_code == 202, response.text
    assert submitted == [f"Item {index}" for index in range(8)]
    body = response.json()
    assert [run["item_id"] for run in body["definition"]["runs"]] == [f"item-{index}" for index in range(8)]
    assert body["results"]["admission"]["omitted"] == ["item-8"]
    assert body["results"]["admission"]["limit"] == 8
    assert "8 unfinished analyses" in body["results"]["admission"]["reason"]


async def test_no_free_capacity_refuses_the_run_before_any_assessment_is_created(client, store, monkeypatch):
    await login(client, "otto")
    created = await _batch_session(client, 2)
    _queued_runs(monkeypatch, store)

    async def full(_actor):
        return 0

    monkeypatch.setattr(store, "analysis_capacity", full)
    response = await client.post(
        f"/api/analysis-sessions/{created['id']}/runs",
        json={"session_revision": 1, "input_digest": created["input_digest"]},
    )
    assert response.status_code == 429
    assert await store.list_assessments() == []
    assert (await store.get_analysis_session(created["id"])).revision == 1


async def test_running_again_submits_only_the_omitted_connections(client, store, monkeypatch):
    await login(client, "otto")
    created = await _batch_session(client, 3)
    submitted = _queued_runs(monkeypatch, store)
    free = iter([2, 8])

    async def capacity(_actor):
        return next(free)

    monkeypatch.setattr(store, "analysis_capacity", capacity)
    first = await client.post(
        f"/api/analysis-sessions/{created['id']}/runs",
        json={"session_revision": 1, "input_digest": created["input_digest"]},
    )
    assert first.json()["results"]["admission"]["omitted"] == ["item-2"]
    second = await client.post(
        f"/api/analysis-sessions/{created['id']}/runs",
        json={"session_revision": 2, "input_digest": created["input_digest"]},
    )
    assert second.status_code == 202, second.text
    assert submitted == ["Item 0", "Item 1", "Item 2"]
    body = second.json()
    assert [run["item_id"] for run in body["definition"]["runs"]] == ["item-0", "item-1", "item-2"]
    assert "admission" not in body["results"]
    assert set(body["results"]["bindings"]) == {"item-0", "item-1", "item-2"}
    third = await client.post(
        f"/api/analysis-sessions/{created['id']}/runs",
        json={"session_revision": 3, "input_digest": created["input_digest"]},
    )
    assert third.status_code == 422
    assert "already been executed" in third.text


async def test_partial_connection_submission_is_bound_for_recovery(client, store, monkeypatch):
    await login(client, "otto")
    request = {
        "name": "Batch item",
        "destination": "API",
        "sources": ["10.0.0.1"],
        "members": [{"name": "api", "addresses": ["192.0.2.1"]}],
        "condition": {"kind": "member", "member": "api"},
        "success": "forward",
    }
    created = (
        await client.post(
            "/api/analysis-sessions",
            json={
                "title": "Recoverable batch",
                "input": {
                    "kind": "connection",
                    "snapshot": {"snapshot": "100", "manifest_sha256": "abc", "estate": "test"},
                    "connections": [
                        {
                            "id": f"item-{index}",
                            "name": f"Item {index}",
                            "source": {"kind": "inline", "request": request},
                        }
                        for index in range(2)
                    ],
                },
            },
        )
    ).json()
    monkeypatch.setattr(analysis_sessions.assessment_routes, "_definition", lambda *_: {})
    calls = 0

    async def submit(*_args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError("submission failed")
        return SimpleNamespace(id="run-recoverable", state="queued", input_digest="digest")

    monkeypatch.setattr(analysis_sessions.assessment_routes, "submit", submit)
    response = await client.post(
        f"/api/analysis-sessions/{created['id']}/runs",
        json={"session_revision": 1, "input_digest": created["input_digest"]},
    )
    assert response.status_code == 422
    recovered = await store.get_analysis_session(created["id"])
    assert recovered.revision == 2
    assert len(recovered.definition["runs"]) == 1
    assert set(recovered.results["bindings"]) == {"item-0", "item-1"}
    assert recovered.results["execution_error"] == {
        "state": "partial",
        "submitted": 1,
        "requested": 2,
    }


async def test_inline_connection_groups_child_run_without_catalog_service(client, monkeypatch):
    await login(client, "otto")

    async def submit(store, settings, assessment, body, actor):
        return SimpleNamespace(id="run-1", state="queued", input_digest="digest")

    monkeypatch.setattr(analysis_sessions.assessment_routes, "submit", submit)
    input_value = {
        "kind": "connection",
        "snapshot": {"snapshot": "100", "manifest_sha256": "abc", "estate": "test"},
        "connections": [
            {
                "id": "ad-hoc",
                "name": "Ad hoc traffic",
                "source": {
                    "kind": "inline",
                    "request": {
                        "name": "Ad hoc traffic",
                        "destination": "API",
                        "sources": ["10.0.0.1"],
                        "members": [{"name": "api", "addresses": ["192.0.2.1"]}],
                        "condition": {"kind": "member", "member": "api"},
                        "success": "forward",
                    },
                },
            }
        ],
        "changes": [],
        "mode": "possible",
    }
    created = (
        await client.post("/api/analysis-sessions", json={"title": "Ad hoc", "input": input_value})
    ).json()
    executed = await client.post(
        f"/api/analysis-sessions/{created['id']}/runs",
        json={
            "session_revision": created["revision"],
            "input_digest": created["input_digest"],
        },
    )
    assert executed.status_code == 202, executed.text
    assert executed.json()["definition"]["runs"][0] == {
        "id": "run-1",
        "item_id": "ad-hoc",
        "execution": "queued",
        "result": None,
        "coverage": "not_started",
        "result_ref": None,
    }
    assert executed.json()["results"]["bindings"]["ad-hoc"]["assessment_revision"] == 1


async def test_simulation_rejects_scope_larger_than_reviewed_bound(client):
    await login(client, "otto")
    value = simulation_input()
    value["scope"]["flows"].append({"src": "10.0.0.2", "dst": "192.0.2.2", "proto": "tcp", "port": 443})
    value["bounds"]["max_flows"] = 1
    created = (
        await client.post("/api/analysis-sessions", json={"title": "Bounded route change", "input": value})
    ).json()
    executed = await client.post(
        f"/api/analysis-sessions/{created['id']}/runs",
        json={
            "session_revision": created["revision"],
            "input_digest": created["input_digest"],
        },
    )
    assert executed.status_code == 422
    assert "max_flows" in executed.json()["error"]


async def test_viewer_can_read_sessions_but_cannot_create_or_execute(client):
    await login(client, "vera")
    assert (await client.get("/api/analysis-sessions")).status_code == 200
    assert (
        await client.post("/api/analysis-sessions", json={"title": "Denied", "input": simulation_input()})
    ).status_code == 403


async def test_a_session_saved_from_a_chat_step_runs_as_a_reviewed_session(client, store, monkeypatch):
    """A chat simulation saved through POST /api/ai/steps/{id}/analysis-session
    is listed, reads back with the step as its origin, and runs through the
    reviewed revision and input digest like any other session."""
    value = simulation_input()
    monkeypatch.setattr(
        assessment_service, "snapshot_reference", lambda settings, run=None: dict(value["snapshot"])
    )
    await login(client, "otto")
    user_id = (await store.get_user_by_username("otto")).id
    now = datetime.now(UTC)
    conversation = await store.create_conversation(user_id, "changesim", now)
    reply = await store.start_turn(
        user_id, conversation.id, "what if", None, now, per_user_cap=2, global_cap=16
    )
    assert await store.claim_turn(reply.id, "seed", 60, now)
    step = await store.append_step(
        reply.id,
        "change_simulate",
        1,
        {"intents": value["changes"], "flows": value["scope"]["flows"]},
        False,
        "{}",
        now,
        5,
        provenance={
            "snapshot": "100",
            "degraded": False,
            "manifest_sha256": "abc",
            "engine": None,
            "queries": [],
        },
    )

    saved = await client.post(f"/api/ai/steps/{step.id}/analysis-session")
    assert saved.status_code == 201, saved.text
    created = saved.json()
    assert created["definition"]["input"]["changes"] == value["changes"]
    assert created["definition"]["input"]["scope"]["flows"] == value["scope"]["flows"]
    listed = (await client.get("/api/analysis-sessions")).json()["sessions"]
    assert [item["id"] for item in listed] == [created["id"]]
    read = (await client.get(f"/api/analysis-sessions/{created['id']}")).json()
    assert read["results"]["review"]["origin"]["step_id"] == step.id

    executed = await client.post(
        f"/api/analysis-sessions/{created['id']}/runs",
        json={"session_revision": created["revision"], "input_digest": created["input_digest"]},
    )
    assert executed.status_code == 202, executed.text
    assert executed.json()["revision"] == 2
    assert executed.json()["definition"]["runs"][0]["execution"] == "queued"
    assert executed.json()["results"]["review"]["origin"]["step_id"] == step.id


async def test_application_connection_keeps_reviewed_revision_after_catalog_advances(
    client, store, monkeypatch
):
    await login(client, "otto")
    request_body = {
        "name": "Client to API",
        "destination": "API",
        "sources": ["10.0.0.1"],
        "members": [{"name": "api", "addresses": ["192.0.2.1"]}],
        "condition": {"kind": "member", "member": "api"},
        "success": "forward",
    }
    definition = {
        "schema_version": 1,
        "kind": "BusinessApplication",
        "id": "checkout",
        "name": "Checkout",
        "state": "ready",
        "services": [
            {
                "id": "api-service",
                "name": "API",
                "connection_ids": ["client-api"],
                "component_roles": [],
            }
        ],
        "groups": [],
        "connections": [],
    }
    digest = "a" * 64
    await store.create_application_revision(
        definition=definition, digest=digest, created_by=1, expected_revision=0
    )
    snapshot = {
        "snapshot": "100",
        "manifest_sha256": "abc",
        "estate": "test",
        "observation_floor_ms": None,
    }
    scope_digest = "b" * 64
    await store.save_application_resolution(
        {
            "digest": scope_digest,
            "application": {"id": "checkout", "revision": 1, "digest": digest},
            "snapshot": snapshot,
            "connections": [
                {
                    "id": "client-api",
                    "service_id": "api-service",
                    "readiness": "ready",
                    "request": request_body,
                    "issues": [],
                }
            ],
        }
    )

    async def submit(store, settings, assessment, body, actor):
        return SimpleNamespace(id="run-app", state="queued", input_digest="input-app")

    monkeypatch.setattr(analysis_sessions.assessment_routes, "submit", submit)
    created = (
        await client.post(
            "/api/analysis-sessions",
            json={
                "title": "Checkout analysis",
                "input": {
                    "kind": "connection",
                    "snapshot": snapshot,
                    "connections": [
                        {
                            "id": "client-api",
                            "name": "Client to API",
                            "source": {
                                "kind": "application_connection",
                                "reference": {
                                    "application": {
                                        "id": "checkout",
                                        "revision": 1,
                                        "digest": digest,
                                    },
                                    "service_id": "api-service",
                                    "connection_id": "client-api",
                                },
                                "request": request_body,
                                "resolved_scope_digest": scope_digest,
                            },
                        }
                    ],
                },
            },
        )
    ).json()
    await store.create_application_revision(
        definition={**definition, "name": "Checkout revised"},
        digest="c" * 64,
        created_by=1,
        expected_revision=1,
    )

    executed = await client.post(
        f"/api/analysis-sessions/{created['id']}/runs",
        json={
            "session_revision": created["revision"],
            "input_digest": created["input_digest"],
        },
    )
    assert executed.status_code == 202, executed.text
    source = executed.json()["definition"]["input"]["connections"][0]["source"]
    assert source["reference"]["application"]["revision"] == 1
    assert source["resolved_scope_digest"] == scope_digest


async def test_application_connection_rejects_unreviewed_digest(client, store):
    await login(client, "otto")
    definition = {
        "schema_version": 1,
        "kind": "BusinessApplication",
        "id": "checkout",
        "name": "Checkout",
        "state": "ready",
        "services": [],
        "groups": [],
        "connections": [],
    }
    await store.create_application_revision(
        definition=definition, digest="a" * 64, created_by=1, expected_revision=0
    )
    request_body = {
        "name": "Ad hoc traffic",
        "destination": "API",
        "sources": ["10.0.0.1"],
        "members": [{"name": "api", "addresses": ["192.0.2.1"]}],
        "condition": {"kind": "member", "member": "api"},
        "success": "forward",
    }
    created = (
        await client.post(
            "/api/analysis-sessions",
            json={
                "title": "Bad binding",
                "input": {
                    "kind": "connection",
                    "snapshot": {
                        "snapshot": "100",
                        "manifest_sha256": "abc",
                        "estate": "test",
                    },
                    "connections": [
                        {
                            "id": "client-api",
                            "name": "Client to API",
                            "source": {
                                "kind": "application_connection",
                                "reference": {
                                    "application": {
                                        "id": "checkout",
                                        "revision": 1,
                                        "digest": "d" * 64,
                                    },
                                    "service_id": "api-service",
                                    "connection_id": "client-api",
                                },
                                "request": request_body,
                                "resolved_scope_digest": "e" * 64,
                            },
                        }
                    ],
                },
            },
        )
    ).json()
    executed = await client.post(
        f"/api/analysis-sessions/{created['id']}/runs",
        json={
            "session_revision": created["revision"],
            "input_digest": created["input_digest"],
        },
    )
    assert executed.status_code == 422
    assert "digest" in executed.json()["error"]


def _old_session(runs):
    """A stored session whose inline request holds `choice_scope` and whose run
    summaries hold `outcome`."""
    return {
        "schema_version": 1,
        "id": "old-session",
        "revision": 1,
        "title": "Old session",
        "input": {
            "kind": "connection",
            "snapshot": {"snapshot": "100", "manifest_sha256": "abc", "estate": "test"},
            "connections": [
                {
                    "id": "client-api",
                    "name": "Client to API",
                    "source": {
                        "kind": "inline",
                        "request": {
                            "name": "Client to API",
                            "destination": "API",
                            "sources": ["10.0.0.1"],
                            "members": [{"name": "api", "addresses": ["192.0.2.1"]}],
                            "condition": {"kind": "member", "member": "api"},
                            "success": "forward",
                            "choice_scope": "unspecified",
                        },
                    },
                }
            ],
            "changes": [],
            "mode": "possible",
        },
        "runs": runs,
        "legacy_assessment": None,
    }


_OLD_RUN = {
    "id": "run-old",
    "item_id": "client-api",
    "execution": "queued",
    "outcome": None,
    "result": None,
    "coverage": "not_started",
    "result_ref": None,
}


async def test_a_session_stored_with_outcome_and_choice_scope_is_read(client, store):
    from hst.app.ai.registry import ToolError
    from hst.twin_tools.change import _read_run

    await store.create_analysis_session(
        title="Old session",
        definition=_old_session([_OLD_RUN]),
        results={},
        created_by=1,
        session_id="old-session",
    )
    await login(client, "otto")

    listed = await client.get("/api/analysis-sessions")
    assert listed.status_code == 200, listed.text
    read = await client.get("/api/analysis-sessions/old-session")
    assert read.status_code == 200, read.text
    (summary,) = read.json()["definition"]["runs"]
    assert "outcome" not in summary and summary["execution"] == "queued"
    assert "choice_scope" not in read.text
    exported = await client.get("/api/analysis-sessions/old-session/export")
    assert exported.status_code == 200, exported.text
    run = await client.get("/api/analysis-sessions/old-session/runs/run-old")
    assert (run.status_code, run.json()["error"]) == (404, "Analysis run not found")
    with pytest.raises(ToolError, match="no analysis run 'run-old'"):
        await _read_run(SimpleNamespace(store=store, settings=None), "old-session", "run-old")

    from hst.assessment.store import AnalysisRun

    run_record = AnalysisRun(
        id="run-old",
        assessment_id="old-session",
        assessment_revision=1,
        kind="evaluate",
        inputs={},
        input_digest="f" * 64,
        snapshot_refs=[],
        engine_version="test",
        created_by=1,
        created_at="2026-10-01T00:00:00",
    )
    async with store.assessment_transaction() as tx:
        await tx.put("run", {**run_record.as_dict(), "revision": 1})
    run_export = await client.get("/api/analysis-sessions/old-session/runs/run-old/export")
    assert run_export.status_code == 200, run_export.text
    assert "choice_scope" not in run_export.text
    assert run_export.json()["input"] == read.json()["definition"]["input"]


@pytest.mark.parametrize("outcome", ["holds", "not_holds", "unknown", "not_applicable"])
async def test_a_run_stored_with_an_outcome_and_no_result_is_left_out(client, store, outcome):
    from hst.app.ai.registry import ToolError
    from hst.twin_tools.change import _read_run

    completed = {**_OLD_RUN, "execution": "completed", "outcome": outcome, "coverage": "complete"}
    await store.create_analysis_session(
        title="Old session",
        definition=_old_session([completed]),
        results={},
        created_by=1,
        session_id="old-session",
    )
    await login(client, "otto")

    listed = await client.get("/api/analysis-sessions")
    assert listed.status_code == 200, listed.text
    read = await client.get("/api/analysis-sessions/old-session")
    assert read.status_code == 200, read.text
    assert read.json()["definition"]["runs"] == []
    assert (await client.get("/api/analysis-sessions/old-session/export")).status_code == 200
    run = await client.get("/api/analysis-sessions/old-session/runs/run-old")
    assert (run.status_code, run.json()["error"]) == (404, "Analysis run not found in this session")
    exported_run = await client.get("/api/analysis-sessions/old-session/runs/run-old/export")
    assert exported_run.status_code == 404
    with pytest.raises(ToolError, match="no run 'run-old' in analysis session"):
        await _read_run(SimpleNamespace(store=store, settings=None), "old-session", "run-old")
    # the history serves the revision as GET of the revision does
    history = (await client.get("/api/analysis-sessions/old-session/history")).json()["revisions"]
    assert history[0]["definition"] == read.json()["definition"]
    assert "choice_scope" not in json.dumps(history) and "outcome" not in json.dumps(history)
    again = await client.post(
        "/api/analysis-sessions/old-session/runs",
        json={"session_revision": 1, "input_digest": read.json()["input_digest"]},
    )
    assert again.status_code == 422 and "already been executed" in again.text
    stored = await store.get_analysis_session("old-session")
    assert stored.revision == 1 and stored.definition["runs"] == [completed]


def test_a_stated_outcome_beside_a_result_is_dropped_and_the_result_kept():
    with_result = {**_OLD_RUN, "execution": "completed", "outcome": "not_applicable", "coverage": "complete"}
    with_result["result"] = {"answer": "true"}
    session = analysis_sessions.stored_session(_old_session([with_result]))
    (summary,) = session.runs
    assert summary.result == {"answer": "true"}


async def test_a_body_that_states_a_run_outcome_is_refused(client):
    from pydantic import ValidationError

    from hst.analysis.contracts import AnalysisSession

    with pytest.raises(ValidationError, match="outcome"):
        AnalysisSession.model_validate(_old_session([_OLD_RUN]))


async def test_a_resolution_saved_with_choice_scope_gives_the_reviewed_request(store):
    from hst.analysis.contracts import ApplicationConnection

    request_body = _old_session([])["input"]["connections"][0]["source"]["request"]
    reviewed = {key: value for key, value in request_body.items() if key != "choice_scope"}
    definition = {
        "schema_version": 1,
        "kind": "BusinessApplication",
        "id": "checkout",
        "name": "Checkout",
        "services": [{"id": "api-service", "name": "API", "connection_ids": ["client-api"]}],
        "groups": [],
        "connections": [],
    }
    await store.create_application_revision(
        definition=definition, digest="a" * 64, created_by=1, expected_revision=0
    )
    snapshot = {"snapshot": "100", "manifest_sha256": "abc", "estate": "test", "observation_floor_ms": None}
    await store.save_application_resolution(
        {
            "digest": "b" * 64,
            "application": {"id": "checkout", "revision": 1, "digest": "a" * 64},
            "snapshot": snapshot,
            "connections": [
                {
                    "id": "client-api",
                    "service_id": "api-service",
                    "readiness": "ready",
                    "request": request_body,
                }
            ],
        }
    )
    source = ApplicationConnection.model_validate(
        {
            "reference": {
                "application": {"id": "checkout", "revision": 1, "digest": "a" * 64},
                "service_id": "api-service",
                "connection_id": "client-api",
            },
            "request": reviewed,
            "resolved_scope_digest": "b" * 64,
        }
    )

    request = await analysis_sessions._application_request(store, source, snapshot)

    assert request["name"] == "Client to API" and "choice_scope" not in request
