"""Release scenarios for Analysis sessions: Service identity, Historical
integrity and Mixed execution.

Sessions are created and run through the API. The runs are the store's real
run records, queued by the real submission path; the tests drive them to an
end state with the store's worker operations (claim, finish, cancel)."""

from __future__ import annotations

import pytest
from tests.app.conftest import login
from tests.app.release_scenarios_rig import (
    CHECKOUT_ID,
    CHECKOUT_SERVICE,
    CHECKOUT_YAML,
    Inventory,
    ScenarioStore,
    api_interface,
    commit_yaml,
    install,
    reference,
)

from hst.assessment.evaluation import RequestBody
from hst.results.project import condition_result

# The connections of Checkout whose sources and members are one address
# family.
SERVICE_CONNECTIONS = ["frontend-to-api", "api-to-database"]


def _normalized(request: dict) -> dict:
    return RequestBody.model_validate(request).model_dump(mode="json", exclude_none=True)


@pytest.fixture
def store():
    return ScenarioStore()


async def _resolved_checkout(client, snapshot: str, revision: int | None = None) -> dict:
    body: dict = {"snapshot": snapshot}
    if revision is not None:
        body["revision"] = revision
    response = await client.post(f"/api/business-applications/{CHECKOUT_ID}/resolve", json=body)
    assert response.status_code == 200, response.text
    assert response.json()["ready"] is True, response.json()["issues"]
    return response.json()


def _selection(resolution: dict, connection_id: str, service_id: str = CHECKOUT_SERVICE) -> dict:
    connection = next(item for item in resolution["connections"] if item["id"] == connection_id)
    return {
        "id": connection_id,
        "name": connection["request"]["name"],
        "source": {
            "kind": "application_connection",
            "reference": {
                "application": {
                    "id": resolution["application"]["id"],
                    "revision": resolution["application"]["revision"],
                    "digest": resolution["application"]["digest"],
                },
                "service_id": service_id,
                "connection_id": connection_id,
            },
            "request": connection["request"],
            "resolved_scope_digest": resolution["digest"],
        },
    }


async def _session(client, title: str, snapshot: dict, connections: list[dict]) -> dict:
    created = await client.post(
        "/api/analysis-sessions",
        json={
            "title": title,
            "input": {"kind": "connection", "snapshot": snapshot, "connections": connections},
        },
    )
    assert created.status_code == 201, created.text
    return created.json()


async def _run(client, session: dict):
    return await client.post(
        f"/api/analysis-sessions/{session['id']}/runs",
        json={"session_revision": session["revision"], "input_digest": session["input_digest"]},
    )


async def test_one_explicit_service_runs_several_connections_as_separate_bound_items(
    client, store, monkeypatch
):
    install(monkeypatch, Inventory("4000", {"4000": api_interface("10.20.0.10")}))
    await login(client, "otto")
    assert (await commit_yaml(client, CHECKOUT_YAML)).status_code == 201
    resolution = await _resolved_checkout(client, "4000")

    session = await _session(
        client,
        "Checkout frontend",
        resolution["snapshot"],
        [_selection(resolution, connection_id) for connection_id in SERVICE_CONNECTIONS],
    )
    executed = await _run(client, session)
    assert executed.status_code == 202, executed.text
    body = executed.json()

    sources = {item["id"]: item["source"] for item in body["definition"]["input"]["connections"]}
    assert list(sources) == SERVICE_CONNECTIONS
    for connection_id, source in sources.items():
        assert source["kind"] == "application_connection"
        assert source["reference"] == {
            "application": {
                "id": CHECKOUT_ID,
                "revision": 1,
                "digest": resolution["application"]["digest"],
            },
            "service_id": CHECKOUT_SERVICE,
            "connection_id": connection_id,
        }
        assert source["resolved_scope_digest"] == resolution["digest"]

    # one independently reported run per connection, each with its own assessment
    runs = body["definition"]["runs"]
    assert sorted(run["item_id"] for run in runs) == sorted(SERVICE_CONNECTIONS)
    assert len({run["id"] for run in runs}) == 2
    bindings = body["results"]["bindings"]
    assert set(bindings) == set(SERVICE_CONNECTIONS)
    assert len({binding["assessment_id"] for binding in bindings.values()}) == 2
    stored = {run.id: run for run in await store.list_analysis_runs()}
    assert set(stored) == {run["id"] for run in runs}
    resolved = {item["id"]: item["request"] for item in resolution["connections"]}
    for run in runs:
        record = stored[run["id"]]
        assert record.assessment_id == bindings[run["item_id"]]["assessment_id"]
        assert _normalized(record.inputs["definition"]["request"]) == resolved[run["item_id"]]

    # a connection claimed for a service that does not list it is refused
    foreign = await _session(
        client,
        "Not this service",
        resolution["snapshot"],
        [_selection(resolution, "frontend-to-api", service_id="billing")],
    )
    refused = await _run(client, foreign)
    assert refused.status_code == 422
    assert "not explicitly associated" in refused.json()["error"]
    assert len(await store.list_analysis_runs()) == 2


PASSING = {"result": condition_result("holds").model_dump(mode="json")}


async def _finish(store, outcomes: dict[str, str]) -> None:
    """Claim each queued run and end it in the state `outcomes` names for its
    id: completed with a passing result, or failed with no result."""
    for _ in outcomes:
        claimed = await store.claim_analysis("release-test")
        assert claimed is not None and claimed.id in outcomes
        state = outcomes[claimed.id]
        assert await store.finish_analysis(
            claimed.id,
            claimed.lease_token,
            result=PASSING if state == "completed" else {},
            state=state,
            error="worker failed" if state == "failed" else None,
        )
    assert await store.claim_analysis("release-test") is None


async def test_an_old_session_stays_bound_to_its_snapshot_revision_and_evidence(client, store, monkeypatch):
    """Historical integrity: advance inventory and application revisions; old
    runs, inputs and evidence export remain bound to their originals."""
    inventory = Inventory("4000", {"4000": api_interface("10.20.0.10"), "4001": api_interface("10.20.0.99")})
    install(monkeypatch, inventory)
    await login(client, "otto")
    assert (await commit_yaml(client, CHECKOUT_YAML)).status_code == 201
    old_resolution = await _resolved_checkout(client, "4000")
    old_request = next(item for item in old_resolution["connections"] if item["id"] == "frontend-to-api")[
        "request"
    ]
    session = await _session(
        client, "Frontend to API", old_resolution["snapshot"], [_selection(old_resolution, "frontend-to-api")]
    )
    executed = await _run(client, session)
    assert executed.status_code == 202, executed.text
    (run,) = executed.json()["definition"]["runs"]
    await _finish(store, {run["id"]: "completed"})

    def read_all():
        return (
            client.get(f"/api/analysis-sessions/{session['id']}"),
            client.get(f"/api/analysis-sessions/{session['id']}/export"),
            client.get(f"/api/analysis-sessions/{session['id']}/runs/{run['id']}/export"),
            client.get(f"/api/business-applications/{CHECKOUT_ID}/export", params={"revision": 1}),
        )

    before = [await request for request in read_all()]
    assert all(response.status_code == 200 for response in before)

    # the inventory advances to 4001, where the API interface has another address
    inventory.latest = "4001"
    # the application advances to revision 2
    current = (await client.get(f"/api/business-applications/{CHECKOUT_ID}")).json()["application"]
    revised = await client.put(
        f"/api/business-applications/{CHECKOUT_ID}",
        json={
            "definition": {**current["definition"], "name": "Checkout revised"},
            "expected_revision": 1,
            "source": "editor",
        },
    )
    assert revised.status_code == 200, revised.text
    new_resolution = await _resolved_checkout(client, "4001")
    assert new_resolution["application"]["revision"] == 2
    assert new_resolution["digest"] != old_resolution["digest"]
    newer = await _session(
        client,
        "Frontend to API again",
        new_resolution["snapshot"],
        [_selection(new_resolution, "frontend-to-api")],
    )
    rerun = await _run(client, newer)
    assert rerun.status_code == 202, rerun.text
    (new_run,) = rerun.json()["definition"]["runs"]
    await _finish(store, {new_run["id"]: "completed"})
    assert new_run["id"] != run["id"]

    after = [await request for request in read_all()]
    assert [response.content for response in after] == [response.content for response in before]

    # and in absolute terms, the originals
    exported = after[1].json()
    source = exported["definition"]["input"]["connections"][0]["source"]
    assert exported["definition"]["input"]["snapshot"] == reference("4000")
    assert source["reference"]["application"]["revision"] == 1
    assert source["resolved_scope_digest"] == old_resolution["digest"]
    assert source["request"]["members"][0]["addresses"] == ["10.20.0.10"]
    saved_run = exported["run_results"][run["id"]]
    assert saved_run["snapshot_refs"] == [reference("4000")]
    assert _normalized(saved_run["inputs"]["definition"]["request"]) == old_request
    assert saved_run["state"] == "completed"
    assert exported["results"]["bindings"]["frontend-to-api"]["input_digest"] == saved_run["input_digest"]
    run_export = after[2].json()
    assert run_export["run"]["snapshot_refs"] == [reference("4000")]
    assert run_export["input"] == exported["definition"]["input"]
    stored_resolution = await store.get_application_resolution(old_resolution["digest"])
    assert {
        key: value for key, value in stored_resolution.items() if key not in {"id", "revision"}
    } == old_resolution
    assert "name: Checkout\n" in after[3].text


def _inline(index: int) -> dict:
    # a distinct destination each, so no two runs share an input digest
    request = {
        "name": f"Item {index}",
        "destination": "API",
        "sources": ["192.0.2.10"],
        "members": [{"name": "api", "addresses": [f"198.51.100.{index + 1}"]}],
        "condition": {"kind": "member", "member": "api"},
        "success": "forward",
    }
    return {"id": f"item-{index}", "name": f"Item {index}", "source": {"kind": "inline", "request": request}}


async def test_a_failed_and_a_cancelled_child_leave_the_session_incomplete(client, store, monkeypatch):
    install(monkeypatch, Inventory("4000", {"4000": {}}))
    await login(client, "otto")
    session = await _session(client, "Mixed", reference("4000"), [_inline(index) for index in range(3)])
    executed = await _run(client, session)
    assert executed.status_code == 202, executed.text
    run_of = {run["item_id"]: run["id"] for run in executed.json()["definition"]["runs"]}
    assert set(run_of) == {"item-0", "item-1", "item-2"}

    cancelled = await store.cancel_analysis(run_of["item-2"])
    assert cancelled is not None and cancelled.state == "cancelled"
    await _finish(store, {run_of["item-0"]: "completed", run_of["item-1"]: "failed"})

    read = await client.get(f"/api/analysis-sessions/{session['id']}")
    assert read.status_code == 200, read.text
    runs = {run["item_id"]: run for run in read.json()["definition"]["runs"]}
    assert runs["item-0"]["execution"] == "completed"
    assert runs["item-0"]["result"]["answer"] == "true"
    assert runs["item-0"]["coverage"] == "complete"
    for item, state in (("item-1", "failed"), ("item-2", "cancelled")):
        assert runs[item]["execution"] == state
        assert runs[item]["result"] is None
        assert runs[item]["coverage"] != "complete"
    # the session states no success of its own: its results hold the bindings
    # only, and the children it is derived from are not all completed and passing
    assert set(read.json()["results"]) == {"bindings"}
    assert not all(
        run["execution"] == "completed"
        and run["coverage"] == "complete"
        and (run["result"] or {}).get("answer") == "true"
        for run in runs.values()
    )
    exported = (await client.get(f"/api/analysis-sessions/{session['id']}/export")).json()
    assert {summary["state"] for summary in exported["run_results"].values()} == {
        "completed",
        "failed",
        "cancelled",
    }


async def test_an_old_and_a_new_session_run_stay_readable_for_a_comparison(client, store, monkeypatch):
    """Historical integrity, run comparison: the snapshot advances, a second
    session runs at the new snapshot, and each session returns its own run with
    its own snapshot, session revision and input digest."""
    inventory = Inventory("4000", {"4000": api_interface("10.20.0.10"), "4001": api_interface("10.20.0.99")})
    install(monkeypatch, inventory)
    await login(client, "otto")
    assert (await commit_yaml(client, CHECKOUT_YAML)).status_code == 201

    async def run_at(snapshot: str, title: str) -> tuple[dict, dict]:
        resolution = await _resolved_checkout(client, snapshot)
        session = await _session(
            client, title, resolution["snapshot"], [_selection(resolution, "frontend-to-api")]
        )
        executed = await _run(client, session)
        assert executed.status_code == 202, executed.text
        (run,) = executed.json()["definition"]["runs"]
        await _finish(store, {run["id"]: "completed"})
        return session, run

    old_session, old_run = await run_at("4000", "Frontend to API")
    old_url = f"/api/analysis-sessions/{old_session['id']}/runs/{old_run['id']}"
    before = await client.get(old_url)
    assert before.status_code == 200, before.text

    inventory.latest = "4001"
    new_session, new_run = await run_at("4001", "Frontend to API again")
    new = await client.get(f"/api/analysis-sessions/{new_session['id']}/runs/{new_run['id']}")
    assert new.status_code == 200, new.text
    after = await client.get(old_url)
    assert after.content == before.content

    old_value, new_value = after.json(), new.json()
    assert old_value["run"]["snapshot_refs"] == [reference("4000")]
    assert new_value["run"]["snapshot_refs"] == [reference("4001")]
    assert old_value["run"]["input_digest"] != new_value["run"]["input_digest"]
    assert old_value["summary"]["id"] == old_run["id"] and new_value["summary"]["id"] == new_run["id"]
