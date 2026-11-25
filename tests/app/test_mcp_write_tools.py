"""The MCP write tools on the HTTP transport: who is offered them, and what
each one records."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import pytest
from tests.app.fakes import FakeStore
from tests.app.test_mcp_http import TOOLS_LIST, _call, _enable, _issue, _mcp, _tool_names
from tests.test_business_applications import one_connection_definition
from tests.twin_tools_fakes import FakeGraph, install, settings

from hst.app.ai import mcp as ai_mcp
from hst.app.ai.registry import Principal, ToolContext
from hst.app.routes import analysis_sessions
from hst.assessment import service as assessment_service
from hst.assessment.store import MAX_PENDING_PER_ACTOR, MemoryAssessmentStore
from hst.twin_tools import write as write_tools
from hst.twin_tools import write_registry
from hst.twin_tools.write import ChangeSubmitSimulationResult

pytest.importorskip("mcp")

WRITE_TOOLS = [
    "change_submit_simulation",
    "app_save_application",
    "assessment_submit_run",
    "assessment_cancel_run",
]
IN_APP_SURFACES = ["drawer", "changesim", "assessment_qa", "assessment_draft", "service_generator", "rest"]
CHANGES = [{"kind": "fw_rule.add", "params": {"device": "dev:fw1"}}]
FLOW = {"src": "10.0.0.1", "dst": "192.0.2.1", "proto": "tcp", "port": 443}
UNPUBLISHED = assessment_service.snapshot_reference


class WriteFakeStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return WriteFakeStore()


def _reference(settings, value=None):
    snapshot = str(value) if value else "4000"
    return {
        "snapshot": snapshot,
        "manifest_sha256": f"digest-{snapshot}",
        "estate": "test",
        "observation_floor_ms": None,
    }


@pytest.fixture(autouse=True)
def wired(monkeypatch):
    """A graph whose pointer names run 4000 and retains 3000 and 4000, and
    snapshot references with an evidence manifest for every run."""
    graph = install(monkeypatch, FakeGraph())
    monkeypatch.setattr(ai_mcp, "Settings", lambda: settings())
    monkeypatch.setattr(assessment_service, "snapshot_reference", _reference)
    monkeypatch.setattr(assessment_service, "engine_version", lambda settings: "engine-test")
    return graph


def _definition() -> dict:
    return one_connection_definition("device", "dev:core1").model_dump(mode="json")


async def _assessment(store, *, snapshot: str | None = None):
    definition: dict = {"intents": [], "mode": "possible"}
    if snapshot is not None:
        definition["snapshot"] = snapshot
    return await store.create_assessment(
        title="Checkout", purpose="evaluation", definition=definition, created_by=1
    )


async def _queued(store, assessment, actor: int, n: int = 0):
    return await store.enqueue_analysis(
        assessment_id=assessment.id,
        assessment_revision=assessment.revision,
        kind="evaluate",
        inputs={"n": n},
        snapshot_refs=[_reference(None, "4000")],
        engine_version="engine-test",
        created_by=actor,
    )


async def _write_token(app, store, username: str = "otto") -> str:
    token = (await _issue(app, username, scope="read-write"))["token"]
    await _enable(store)
    return token


async def _tool(app, token: str, name: str, arguments: dict) -> dict:
    r = await _mcp(app, token, _call(name, arguments))
    assert r.status_code == 200, r.text
    return r.json()["result"]


def _minimal(assessment_id: str, run_id: str) -> dict[str, dict]:
    return {
        "change_submit_simulation": {"title": "Open 443", "changes": CHANGES},
        "app_save_application": {"definition": _definition()},
        "assessment_submit_run": {"assessment_id": assessment_id},
        "assessment_cancel_run": {"run_id": run_id},
    }


# --- criterion 1: who is offered the write tools ------------------------------------------


async def test_a_read_write_token_of_an_operator_lists_the_write_tools_with_their_annotations(app, store):
    token = await _write_token(app, store)

    r = await _mcp(app, token, TOOLS_LIST)

    tools = {tool["name"]: tool for tool in r.json()["result"]["tools"]}
    assert set(WRITE_TOOLS) <= set(tools)
    hints = {
        name: (
            tools[name]["annotations"]["readOnlyHint"],
            tools[name]["annotations"]["destructiveHint"],
            tools[name]["annotations"]["idempotentHint"],
            tools[name]["annotations"]["openWorldHint"],
        )
        for name in WRITE_TOOLS
    }
    assert hints == {
        "change_submit_simulation": (False, False, False, False),
        "app_save_application": (False, True, False, False),
        "assessment_submit_run": (False, False, False, False),
        "assessment_cancel_run": (False, True, True, False),
    }


@pytest.mark.parametrize(
    ("username", "scope"), [("otto", "read"), ("ada", "read"), ("vera", "read"), ("vera", "read-write")]
)
async def test_a_read_token_or_a_viewer_token_lists_no_write_tool(app, store, username, scope):
    token = (await _issue(app, username, scope=scope))["token"]
    await _enable(store)

    names = await _tool_names(app, token)

    assert not set(WRITE_TOOLS) & set(names)
    assert "change_get_simulation" in names


@pytest.mark.parametrize("name", WRITE_TOOLS)
async def test_a_read_token_that_calls_a_write_tool_gets_forbidden(app, store, name):
    otto = await store.get_user_by_username("otto")
    assessment = await _assessment(store)
    run = await _queued(store, assessment, otto.id)
    token = (await _issue(app, "otto"))["token"]
    await _enable(store)

    result = await _tool(app, token, name, _minimal(assessment.id, run.id)[name])

    assert result["isError"] is True
    assert result["structuredContent"]["error"]["code"] == "forbidden"
    # nothing was written
    assert await store.list_analysis_sessions() == []
    assert await store.list_applications() == []
    assert [(r.id, r.state) for r in await store.list_analysis_runs(assessment.id)] == [(run.id, "queued")]
    (event,) = store.ai_events
    assert (event.user_id, event.tool, event.outcome, event.error_class) == (
        otto.id,
        name,
        "error",
        "PermissionError",
    )


async def test_a_viewer_read_write_token_that_calls_a_write_tool_gets_permission_denied(app, store):
    token = await _write_token(app, store, "vera")

    result = await _tool(app, token, "app_save_application", {"definition": _definition()})

    assert result["isError"] is True
    assert result["structuredContent"]["error"]["code"] == "permission_denied"
    assert await store.list_applications() == []


async def test_the_local_principal_is_offered_no_write_tool_and_a_call_is_forbidden():
    from hst.mcp_server import build_server

    server = build_server(Principal.local(store=True))

    names = {tool.name for tool in await server.list_tools()}
    res = await server.call_tool("app_save_application", {"definition": _definition()})

    assert not names & set(WRITE_TOOLS)
    assert res.is_error is True
    assert res.structured_content["error"]["code"] == "forbidden"


def test_the_registry_offers_the_write_tools_only_to_a_read_write_token_on_mcp():
    registry = write_registry()
    operator_token = Principal.for_token(user_id=2, role="operator", scope="read-write")

    assert [spec.name for spec in registry.offered(operator_token, "mcp")] == WRITE_TOOLS
    assert all(spec.kind == "write" and spec.surfaces == frozenset({"mcp"}) for spec in registry.specs())
    assert all(spec.permission == "changes.write" for spec in registry.specs())
    for principal in (
        Principal.for_token(user_id=2, role="operator", scope="read"),
        Principal.for_token(user_id=1, role="viewer", scope="read-write"),
        Principal.for_role("admin", user_id=3, origin="mcp"),
        Principal.local(store=True),
    ):
        assert registry.offered(principal, "mcp") == [], principal


@pytest.mark.parametrize("surface", IN_APP_SURFACES)
def test_no_in_app_surface_offers_or_runs_a_write_tool(surface):
    registry = write_registry()
    admin_token = Principal.for_token(user_id=3, role="admin", scope="read-write")

    for principal in (Principal.for_role("admin", user_id=3), admin_token):
        assert registry.offered(principal, surface) == [], principal
    outcome = registry.invoke(
        ToolContext(settings=settings(), principal=admin_token, surface=surface),
        "assessment_cancel_run",
        {"run_id": "r1"},
    )
    assert outcome.is_error is True
    assert outcome.error is not None and outcome.error["error"]["code"] == "forbidden"


# --- criterion 2: latest without a manifest -------------------------------------------------


@pytest.mark.parametrize("name", ["change_submit_simulation", "assessment_submit_run"])
async def test_latest_without_a_manifest_is_snapshot_not_published(app, store, monkeypatch, name):
    # the real reference: the fake settings have no manifests directory
    monkeypatch.setattr(assessment_service, "snapshot_reference", UNPUBLISHED)
    assessment = await _assessment(store)
    token = await _write_token(app, store)
    arguments = {
        "change_submit_simulation": {"title": "Open 443", "changes": CHANGES},
        "assessment_submit_run": {"assessment_id": assessment.id, "snapshot": "latest"},
    }[name]

    result = await _tool(app, token, name, arguments)

    assert result["isError"] is True
    error = result["structuredContent"]["error"]
    assert (error["code"], error["field"]) == ("snapshot_not_published", "snapshot")
    assert "evidence manifest" in error["message"]
    assert await store.list_analysis_sessions() == []
    assert await store.list_analysis_runs(assessment.id) == []


# --- criterion 3: the per-actor cap ----------------------------------------------------------


async def test_the_per_actor_cap_applies_to_assessment_submit_run(app, store):
    otto = await store.get_user_by_username("otto")
    assessment = await _assessment(store)
    for n in range(MAX_PENDING_PER_ACTOR):
        await _queued(store, assessment, otto.id, n)
    otto_token = await _write_token(app, store)
    ada_token = await _write_token(app, store, "ada")

    capped = await _tool(app, otto_token, "assessment_submit_run", {"assessment_id": assessment.id})
    other = await _tool(app, ada_token, "assessment_submit_run", {"assessment_id": assessment.id})

    assert capped["isError"] is True
    assert capped["structuredContent"]["error"]["code"] == "limit_exceeded"
    assert capped["structuredContent"]["error"]["retryable"] is True
    # the cap counts each user's own unfinished runs
    assert other["isError"] is False, other
    ada = await store.get_user_by_username("ada")
    runs = await store.list_analysis_runs(assessment.id, limit=100)
    assert sorted(r.created_by for r in runs) == sorted([otto.id] * MAX_PENDING_PER_ACTOR + [ada.id])


async def test_the_per_actor_cap_applies_to_change_submit_simulation_before_a_session_is_saved(app, store):
    otto = await store.get_user_by_username("otto")
    assessment = await _assessment(store)
    for n in range(MAX_PENDING_PER_ACTOR):
        await _queued(store, assessment, otto.id, n)
    token = await _write_token(app, store)

    result = await _tool(app, token, "change_submit_simulation", {"title": "Open 443", "changes": CHANGES})

    assert result["isError"] is True
    assert result["structuredContent"]["error"]["code"] == "limit_exceeded"
    assert await store.list_analysis_sessions() == []


# --- what each tool records ------------------------------------------------------------------


async def test_change_submit_simulation_saves_a_session_and_queues_its_run_for_the_token_user(app, store):
    otto = await store.get_user_by_username("otto")
    token = await _write_token(app, store)

    result = await _tool(
        app,
        token,
        "change_submit_simulation",
        {"title": "Open 443", "changes": CHANGES, "scope": {"flows": [FLOW]}, "bounds": {"max_seconds": 60}},
    )

    assert result["isError"] is False, result
    envelope = result["structuredContent"]
    body = ChangeSubmitSimulationResult.model_validate(envelope["result"])
    assert body.execution == "queued"
    assert body.snapshot_reference == _reference(None, "4000")
    assert envelope["evidence"]["result"]["word"] == "stored record"
    assert envelope["snapshot"]["id"] == "4000"
    assert envelope["provenance"]["actor"] == str(otto.id)
    session = await store.get_analysis_session(body.session_id)
    assert (session.revision, session.created_by) == (body.session_revision, otto.id) == (2, otto.id)
    assert session.definition["input"]["snapshot"]["snapshot"] == "4000"
    run = await store.get_analysis_run(body.run_id)
    assert (run.kind, run.state, run.created_by, run.limits) == (
        "simulation",
        "queued",
        otto.id,
        {"max_seconds": 60},
    )
    assert run.inputs["analysis_session_simulation"]["scope"]["flows"] == [FLOW]
    (event,) = store.ai_events
    assert (event.user_id, event.tool, event.outcome) == (otto.id, "change_submit_simulation", "ok")


async def test_change_submit_simulation_refuses_more_flows_than_its_bound(app, store):
    token = await _write_token(app, store)

    result = await _tool(
        app,
        token,
        "change_submit_simulation",
        {
            "title": "Open 443",
            "changes": CHANGES,
            "scope": {"flows": [FLOW, FLOW]},
            "bounds": {"max_flows": 1},
        },
    )

    assert result["structuredContent"]["error"]["code"] == "invalid_argument"
    assert result["structuredContent"]["error"]["field"] == "scope"
    assert await store.list_analysis_sessions() == []


async def test_change_submit_simulation_passes_protected_requirements_and_the_change_revision_to_the_run(
    app, store
):
    request = {
        "name": "API",
        "destination": "API",
        "sources": ["10.0.0.1"],
        "members": [{"name": "api", "addresses": ["192.0.2.1"]}],
        "condition": {"kind": "member", "member": "api"},
    }
    token = await _write_token(app, store)

    result = await _tool(
        app,
        token,
        "change_submit_simulation",
        {
            "title": "Open 443",
            "changes": CHANGES,
            "change_revision": {"id": "change-1", "revision": 2},
            "protected": [{"kind": "inline", "name": "API", "request": request, "desired": "isolated"}],
        },
    )

    assert result["isError"] is False, result
    run = await store.get_analysis_run(result["structuredContent"]["result"]["run_id"])
    simulation = run.inputs["analysis_session_simulation"]
    assert simulation["change_revision"] == {"id": "change-1", "revision": 2, "digest": None}
    (protected,) = simulation["protected"]
    assert (protected["kind"], protected["name"], protected["desired"]) == ("inline", "API", "isolated")
    assert protected["request"]["members"][0]["addresses"] == ["192.0.2.1"]
    (requested,) = run.inputs["protected_requests"]
    assert (requested["destination"], requested["sources"]) == ("API", ["10.0.0.1"])


async def test_change_submit_simulation_names_the_saved_session_when_the_cycle_lock_stays_held(
    app, store, monkeypatch
):
    @asynccontextmanager
    async def held(on_lost=None):
        # a collection cycle that holds the lock past the call
        await asyncio.Event().wait()
        yield 0

    monkeypatch.setattr(store, "cycle_lock", held)
    monkeypatch.setattr(write_tools, "LOCK_DEADLINE_S", 0.2)
    token = await _write_token(app, store)

    result = await _tool(app, token, "change_submit_simulation", {"title": "Open 443", "changes": CHANGES})

    assert result["isError"] is True
    error = result["structuredContent"]["error"]
    (session,) = await store.list_analysis_sessions()
    assert (error["code"], error["retryable"]) == ("timeout", False)
    assert error["message"].startswith(f"analysis session {session.id} is saved as revision 1, ")
    assert "cycle lock" in error["message"]
    assert (session.revision, session.definition["runs"]) == (1, [])
    assert await store.list_analysis_runs() == []


async def test_change_submit_simulation_names_the_saved_session_when_the_store_fails_after_saving_it(
    app, store, monkeypatch
):
    async def unreachable(*args, **kwargs):
        raise OSError("connection reset")

    monkeypatch.setattr(analysis_sessions, "run_session", unreachable)
    token = await _write_token(app, store)

    result = await _tool(app, token, "change_submit_simulation", {"title": "Open 443", "changes": CHANGES})

    error = result["structuredContent"]["error"]
    (session,) = await store.list_analysis_sessions()
    assert (error["code"], error["retryable"]) == ("engine_unavailable", False)
    assert error["message"].startswith(f"analysis session {session.id} is saved as revision 1, ")
    assert await store.list_analysis_runs() == []


async def test_assessment_submit_run_queues_nothing_and_may_retry_when_the_cycle_lock_stays_held(
    app, store, monkeypatch
):
    @asynccontextmanager
    async def held(on_lost=None):
        # a collection cycle that holds the lock past the call
        await asyncio.Event().wait()
        yield 0

    assessment = await _assessment(store)
    monkeypatch.setattr(store, "cycle_lock", held)
    monkeypatch.setattr(write_tools, "LOCK_DEADLINE_S", 0.2)
    token = await _write_token(app, store)

    result = await _tool(app, token, "assessment_submit_run", {"assessment_id": assessment.id})

    error = result["structuredContent"]["error"]
    assert (error["code"], error["retryable"]) == ("timeout", True)
    assert "cycle lock" in error["message"] and error["message"].endswith("no run was queued")
    assert await store.list_analysis_runs(assessment.id) == []


async def test_assessment_submit_run_is_not_retryable_when_its_bound_ends_after_the_lock_was_taken(
    app, store, monkeypatch
):
    from hst.app.routes import assessments as assessment_routes

    async def slow(*args, **kwargs):
        # the app store bound ends the call while the run is being queued
        raise TimeoutError

    assessment = await _assessment(store)
    monkeypatch.setattr(assessment_routes, "submit", slow)
    token = await _write_token(app, store)

    result = await _tool(app, token, "assessment_submit_run", {"assessment_id": assessment.id})

    error = result["structuredContent"]["error"]
    assert (error["code"], error["retryable"]) == ("timeout", False)
    assert error["message"].startswith(
        f"the call could not confirm that a run of assessment {assessment.id} was queued: "
    )


async def test_app_save_application_creates_and_revises_with_the_token_user_as_author(app, store):
    otto = await store.get_user_by_username("otto")
    token = await _write_token(app, store)
    definition = _definition()

    created = await _tool(app, token, "app_save_application", {"definition": definition})
    revised = await _tool(
        app,
        token,
        "app_save_application",
        {"definition": {**definition, "name": "Webshop EU"}, "expected_revision": 1},
    )
    stale = await _tool(
        app,
        token,
        "app_save_application",
        {"definition": {**definition, "name": "Webshop US"}, "expected_revision": 1},
    )

    assert created["isError"] is False, created
    assert created["structuredContent"]["result"]["revision"] == 1
    assert created["structuredContent"]["result"]["unchanged"] is False
    assert revised["structuredContent"]["result"]["revision"] == 2
    assert stale["isError"] is True
    assert stale["structuredContent"]["error"]["code"] == "conflict"
    stored = await store.get_application("webshop")
    assert (stored.revision, stored.name, stored.created_by) == (2, "Webshop EU", otto.id)


async def test_app_save_application_records_the_api_origin_without_a_validation(app, store):
    token = await _write_token(app, store)

    created = await _tool(app, token, "app_save_application", {"definition": _definition()})

    assert created["isError"] is False, created
    stored = await store.get_application("webshop")
    assert stored.origin == {
        "source": "api",
        "generation_id": None,
        "generated_digest": None,
        "validation": None,
    }


async def test_app_save_application_refuses_an_existing_application_at_expected_revision_0(app, store):
    token = await _write_token(app, store)
    await _tool(app, token, "app_save_application", {"definition": _definition()})

    again = await _tool(
        app, token, "app_save_application", {"definition": {**_definition(), "name": "Other"}}
    )

    assert again["structuredContent"]["error"]["code"] == "conflict"


async def test_app_save_application_names_the_invalid_part_of_the_definition(app, store):
    token = await _write_token(app, store)
    definition = {key: value for key, value in _definition().items() if key != "name"}

    result = await _tool(app, token, "app_save_application", {"definition": definition})

    error = result["structuredContent"]["error"]
    assert (error["code"], error["field"]) == ("invalid_argument", "definition")
    assert "definition.name" in error["message"]
    assert await store.list_applications() == []


async def test_assessment_submit_run_without_a_snapshot_uses_the_saved_one(app, store):
    otto = await store.get_user_by_username("otto")
    assessment = await _assessment(store, snapshot="3000")
    token = await _write_token(app, store)

    result = await _tool(app, token, "assessment_submit_run", {"assessment_id": assessment.id})

    assert result["isError"] is False, result
    envelope = result["structuredContent"]
    assert envelope["result"]["snapshot_refs"] == [_reference(None, "3000")]
    assert (envelope["snapshot"]["id"], envelope["snapshot"]["selector"]) == ("3000", "3000")
    run = await store.get_analysis_run(envelope["result"]["run_id"])
    assert (run.state, run.kind, run.created_by) == ("queued", "evaluate", otto.id)
    assert run.inputs["analysis"]["snapshot"] is None


@pytest.mark.parametrize(
    ("snapshot", "saved", "pinned"), [("latest", "3000", "4000"), ("3000", None, "3000")]
)
async def test_assessment_submit_run_pins_the_snapshot_it_names(app, store, snapshot, saved, pinned):
    assessment = await _assessment(store, snapshot=saved)
    token = await _write_token(app, store)

    result = await _tool(
        app, token, "assessment_submit_run", {"assessment_id": assessment.id, "snapshot": snapshot}
    )

    assert result["isError"] is False, result
    run = await store.get_analysis_run(result["structuredContent"]["result"]["run_id"])
    assert run.snapshot_refs == [_reference(None, pinned)]
    assert run.inputs["analysis"]["snapshot"] == pinned


async def test_assessment_submit_run_with_a_saved_snapshot_no_longer_retained_is_snapshot_not_found(
    app, store
):
    assessment = await _assessment(store, snapshot="2500")
    token = await _write_token(app, store)

    result = await _tool(app, token, "assessment_submit_run", {"assessment_id": assessment.id})

    error = result["structuredContent"]["error"]
    assert (error["code"], error["field"]) == ("snapshot_not_found", "snapshot")
    assert error["message"].startswith("the assessment's saved snapshot 2500: ")
    assert await store.list_analysis_runs(assessment.id) == []


async def test_assessment_submit_run_checks_the_kind_and_options(app, store):
    assessment = await _assessment(store)
    token = await _write_token(app, store)

    regression = await _tool(
        app, token, "assessment_submit_run", {"assessment_id": assessment.id, "kind": "regression"}
    )
    unknown = await _tool(
        app, token, "assessment_submit_run", {"assessment_id": assessment.id, "options": {"retry_of": "r1"}}
    )
    limits = await _tool(
        app,
        token,
        "assessment_submit_run",
        {"assessment_id": assessment.id, "options": {"limits": {"max_seconds": 0}}},
    )
    missing = await _tool(app, token, "assessment_submit_run", {"assessment_id": "nope"})

    assert regression["structuredContent"]["error"]["field"] == "before_snapshot"
    assert unknown["structuredContent"]["error"]["field"] == "options"
    assert limits["structuredContent"]["error"]["field"] == "options"
    assert "options.limits.max_seconds" in limits["structuredContent"]["error"]["message"]
    assert missing["structuredContent"]["error"]["code"] == "not_found"
    assert await store.list_analysis_runs(assessment.id) == []


async def test_assessment_cancel_run_cancels_a_queued_run_and_repeats_safely(app, store):
    otto = await store.get_user_by_username("otto")
    assessment = await _assessment(store)
    run = await _queued(store, assessment, otto.id)
    token = await _write_token(app, store)

    first = await _tool(app, token, "assessment_cancel_run", {"run_id": run.id})
    second = await _tool(app, token, "assessment_cancel_run", {"run_id": run.id})
    missing = await _tool(app, token, "assessment_cancel_run", {"run_id": "nope"})

    assert first["isError"] is False, first
    assert first["structuredContent"]["result"]["state"] == "cancelled"
    assert first["structuredContent"]["result"]["snapshot_matches"] is True
    assert second["structuredContent"]["result"]["state"] == "cancelled"
    assert (await store.get_analysis_run(run.id)).state == "cancelled"
    assert missing["structuredContent"]["error"]["code"] == "not_found"
