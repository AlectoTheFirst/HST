"""POST /api/business-applications/validate: stages 1 to 5, and no writes."""

from __future__ import annotations

import copy
import threading
from contextlib import contextmanager

import pytest
from fastapi import HTTPException
from tests.app.conftest import login
from tests.app.fakes import FakeStore
from tests.test_business_applications import GraphReferenceSession

from hst.app.routes import business_applications as routes
from hst.applications import validation, yaml_format
from hst.applications.yaml_format import definition_digest, parse_application_yaml
from hst.assessment import direct
from hst.assessment import service as assessment_service
from hst.assessment.jobs import PROCESS_CAPACITY
from hst.assessment.store import MemoryAssessmentStore
from hst.core import db
from hst.results.project import condition_result

REFERENCE = {
    "snapshot": "4000",
    "manifest_sha256": "a" * 64,
    "estate": "test",
    "observation_floor_ms": None,
}

# The inventory member `web` resolves only in a test that adds its node to the graph.
YAML = """\
schema_version: 1
kind: BusinessApplication
id: webshop
name: Webshop
groups:
  - id: clients
    name: Clients
    members:
      - id: lan
        address: 10.9.0.0/24
  - id: servers
    name: Servers
    members:
      - id: web
        inventory: {kind: ip, uid: 'ip:10.0.0.5'}
connections:
  - id: web
    name: Web
    source: clients
    destination: servers
    protocol: tcp
    destination_ports: [443]
    destination_condition: {kind: member, member: web}
services:
  - id: shop
    name: Shop
    connection_ids: [web]
"""


class ApplicationFakeStore(MemoryAssessmentStore, FakeStore):
    pass


class PinnedGraph(GraphReferenceSession):
    """The graph session of the pinned snapshot, and the snapshot ids requested."""

    def __init__(self) -> None:
        super().__init__({})
        self.requested: list[str] = []


@pytest.fixture
def store():
    return ApplicationFakeStore()


@pytest.fixture
def graph(monkeypatch):
    """The pinned snapshot and a graph session that holds only the nodes a test adds."""
    session = PinnedGraph()

    def snapshot_reference(settings, value):
        session.requested.append(value)
        return REFERENCE

    monkeypatch.setattr(assessment_service, "snapshot_reference", snapshot_reference)

    @contextmanager
    def fake_session(settings, **kwargs):
        yield session

    monkeypatch.setattr(db, "session", fake_session)
    return session


def _ip_node(graph: PinnedGraph) -> None:
    graph.nodes["ip:10.0.0.5"] = {"labels": ["Obj", "IpAddress"], "rows": [("10.0.0.5", None)]}


async def _validate(client, **body):
    response = await client.post("/api/business-applications/validate", json={"snapshot": "4000", **body})
    assert response.status_code == 200, response.text
    return response.json()


async def test_a_viewer_validates_and_nothing_is_written(client, store, graph):
    _ip_node(graph)
    await login(client, "vera")
    before = copy.deepcopy(store._assessment_records)

    result = await _validate(client, yaml=YAML)

    assert store._assessment_records == before
    assert await store.list_applications() == []
    assert graph.requested == ["4000"]
    assert result["errors"] == []
    assert result["blocking"] == []
    assert result["snapshot"] == REFERENCE
    assert result["preview"] is None
    assert result["definition"]["id"] == "webshop"
    resolution = result["resolution"]
    assert resolution["ready"] is True
    assert resolution["application"]["revision"] == 0
    assert resolution["connections"][0]["request"]["members"][0]["addresses"] == ["10.0.0.5"]
    assert await store.get_application_resolution(resolution["digest"]) is None


async def test_parse_and_schema_errors_carry_line_numbers(client, store, graph):
    await login(client, "vera")
    broken = YAML.replace("address: 10.9.0.0/24", "address: ten-nine")

    result = await _validate(client, yaml=broken)

    assert result["errors"] == [
        {
            "path": "groups.0.members.0",
            "message": "Value error, address must be an IPv4/IPv6 address or prefix",
            "line": 9,
            "column": 9,
        }
    ]
    assert result["blocking"] == ["groups.0.members.0"]
    assert result["definition"] is None
    assert result["resolution"] is None
    assert graph.params == []

    syntax = await _validate(client, yaml=YAML.replace("  - id: servers", "  - id: servers: x"))
    (error,) = syntax["errors"]
    assert (error["path"], error["line"]) == ("$", 11)
    assert error["message"] == "mapping values are not allowed here"


async def test_every_resolution_issue_blocks_ready(client, store, graph):
    await login(client, "vera")

    result = await _validate(client, yaml=YAML + "state: ready\n")

    assert result["errors"] == []
    codes = {issue["code"]: issue["path"] for issue in result["resolution"]["issues"]}
    assert codes == {
        "inventory-not-found": "groups.servers.members.web",
        "destination-empty": "connections.web.destination",
    }
    assert result["resolution"]["ready"] is False
    assert result["blocking"] == ["groups.servers.members.web", "connections.web.destination"]
    # the authored ready label is kept in the definition; the blocking list is the verdict
    assert result["definition"]["state"] == "ready"

    empty = await _validate(client, yaml="schema_version: 1\nid: empty\nname: Empty\n")
    assert empty["blocking"] == ["selection.connection_ids"]


async def test_address_and_engine_limit_warnings_block_nothing(client, store, graph):
    _ip_node(graph)
    await login(client, "vera")
    many = "".join(f"      - id: host-{index}\n        address: 10.8.0.{index}\n" for index in range(51))
    text = YAML.replace("address: 10.9.0.0/24", "address: 10.9.0.5/24").replace(
        "  - id: servers\n", f"  - id: many\n    name: Many\n    members:\n{many}  - id: servers\n"
    )
    text = text.replace(
        "services:",
        "  - id: many-to-web\n    name: Many\n    source: many\n    destination: servers\n"
        "    destination_condition: {kind: member, member: web}\nservices:",
    )

    result = await _validate(client, yaml=text)

    assert result["errors"] == []
    assert result["warnings"] == [
        {
            "code": "address-normalized",
            "path": "groups.clients.members.lan.address",
            "message": "address 10.9.0.5/24 is stored as 10.9.0.0/24",
        },
        {
            "code": "engine-limit",
            "path": "groups.many",
            "message": "group many has 51 members and is the source of connection many-to-web; "
            "one evaluation request accepts at most 50 source addresses",
        },
    ]
    assert result["definition"]["groups"][0]["members"][0]["address"] == "10.9.0.0/24"
    # the web connection is ready; the oversized source is a resolution issue of its own connection
    assert result["blocking"] == ["connections.many-to-web"]


async def test_merge_validates_the_patch_on_the_current_revision(client, store, graph):
    _ip_node(graph)
    definition = parse_application_yaml(YAML)
    await store.create_application_revision(
        definition=definition.model_dump(mode="json", exclude_none=True),
        digest=definition_digest(definition),
        created_by=1,
        expected_revision=0,
    )
    await login(client, "vera")

    merged = await _validate(client, yaml="schema_version: 1\nid: webshop\nowner: shop-team\n")
    assert merged["errors"] == []
    assert merged["definition"]["owner"] == "shop-team"
    assert [item["id"] for item in merged["definition"]["connections"]] == ["web"]
    assert merged["resolution"]["application"]["revision"] == 1

    replaced = await _validate(
        client, yaml="schema_version: 1\nid: webshop\nowner: shop-team\n", mode="replace"
    )
    (error,) = replaced["errors"]
    # a missing top-level field lies in the document and has no position
    assert (error["path"], error["line"]) == ("name", None)
    assert replaced["resolution"] is None

    dangling = await _validate(
        client,
        yaml="schema_version: 1\nid: webshop\nconnections:\n  - id: extra\n    name: Extra\n"
        "    source: clients\n    destination: nowhere\n"
        "    destination_condition: {kind: member, member: web}\n",
    )
    (error,) = dangling["errors"]
    assert (error["path"], error["line"]) == ("$", None)
    assert "unknown destination group nowhere" in error["message"]
    assert dangling["resolution"] is None


async def test_preview_goes_only_to_a_caller_who_may_commit(client, store, graph):
    _ip_node(graph)
    await login(client, "otto")
    before = copy.deepcopy(store._assessment_records)

    operator = await _validate(client, yaml=YAML, application_id="webshop")
    assert operator["preview"]["application_id"] == "webshop"
    assert operator["preview"]["changes"]["connections_created"] == ["web"]
    assert store._assessment_records == before

    without_id = await _validate(client, yaml=YAML)
    assert without_id["preview"] is None

    mismatch = await _validate(client, yaml=YAML, application_id="checkout")
    (error,) = mismatch["errors"]
    assert (error["path"], error["line"], error["column"]) == ("id", 3, 1)
    assert mismatch["preview"] is None

    await client.post("/api/logout")
    await login(client, "vera")
    viewer = await _validate(client, yaml=YAML, application_id="webshop")
    assert viewer["preview"] is None
    assert viewer["resolution"]["ready"] is True


async def test_validate_is_a_reserved_id_routed_before_the_application_routes(client, store, graph):
    paths = [(method, route.path) for route in routes.router.routes for method in route.methods]
    validate = paths.index(("POST", "/business-applications/validate"))
    assert any("{application_id}" in path for _, path in paths)
    assert all(index > validate for index, (_, path) in enumerate(paths) if "{application_id}" in path)

    await login(client, "otto")
    created = await client.post(
        "/api/business-applications",
        json={"definition": {"schema_version": 1, "id": "validate", "name": "Reserved"}},
    )
    assert created.status_code == 422
    assert "reserved application id" in created.text
    assert await store.list_applications() == []

    result = await _validate(client, yaml=YAML.replace("id: webshop", "id: validate"))
    (error,) = result["errors"]
    assert (error["path"], error["line"]) == ("id", 3)
    assert error["message"] == "Value error, validate is a reserved application id"


async def test_requests_outside_the_body_bounds_are_refused(client, store, graph):
    await login(client, "vera")
    missing_snapshot = await client.post("/api/business-applications/validate", json={"yaml": YAML})
    assert missing_snapshot.status_code == 422
    unknown_field = await client.post(
        "/api/business-applications/validate", json={"yaml": YAML, "snapshot": "4000", "flows": True}
    )
    assert unknown_field.status_code == 422
    assert graph.requested == []


async def test_a_document_of_many_unknown_keys_answers_the_capped_issues(client, store, graph):
    await login(client, "vera")
    unknown = "".join(f"k{index}: 1\n" for index in range(3000))

    result = await _validate(client, yaml=YAML + unknown)

    assert len(result["errors"]) == 101
    assert result["errors"][0] == {
        "path": "k0",
        "message": "Extra inputs are not permitted",
        "line": 28,
        "column": 1,
    }
    assert (
        result["errors"][-1]["message"]
        == "the document has 3000 schema errors and the list holds the first 100"
    )
    assert result["blocking"][-1] == "$"
    assert graph.params == []


async def test_a_parse_without_a_free_slot_answers_503(client, store, graph, monkeypatch):
    slots = threading.BoundedSemaphore(1)
    slots.acquire()
    monkeypatch.setattr(yaml_format, "_PARSE_SLOTS", slots)
    monkeypatch.setattr(yaml_format, "PARSE_WAIT_S", 0.0)
    await login(client, "otto")

    validate = await client.post(
        "/api/business-applications/validate", json={"snapshot": "4000", "yaml": YAML}
    )
    preview = await client.post(
        "/api/business-applications/import/preview", json={"yaml": YAML, "mode": "replace"}
    )

    assert (validate.status_code, preview.status_code) == (503, 503)
    assert validate.json()["error"] == preview.json()["error"] == "Business Application parsing is busy"
    assert await store.list_applications() == []


async def test_a_snapshot_that_cannot_be_pinned_answers_422(client, store, monkeypatch):
    def refuse(settings, value):
        raise ValueError("A published snapshot with an evidence manifest is required.")

    monkeypatch.setattr(assessment_service, "snapshot_reference", refuse)
    await login(client, "vera")

    response = await client.post(
        "/api/business-applications/validate", json={"yaml": YAML, "snapshot": "4000"}
    )

    assert response.status_code == 422
    assert "evidence manifest" in response.text


# Stage 4. The fakes stand in for `direct.evaluate_pinned`: the tests read no
# snapshot manifest and start no child process.


def _outcome(verdict: str, holds=(), fails=(), unknown=()) -> dict:
    """One side of an evaluate result as `evaluate_pinned` returns it, in the result vocabulary."""
    return {
        "result": condition_result(verdict).model_dump(mode="json"),
        "passes": list(holds),
        "fails": list(fails),
        "open": list(unknown),
    }


def _evaluator(monkeypatch, answer):
    """Replace `evaluate_pinned` with `answer(settings, request)` and return the calls."""
    calls: list[dict] = []

    def evaluate_pinned(settings, session, snap, **kwargs):
        calls.append({"session_cts": session.cts, "snapshot": snap.cts, **kwargs})
        return answer(settings, kwargs["request"])

    monkeypatch.setattr(direct, "evaluate_pinned", evaluate_pinned)
    return calls


def _many_connections(count: int, *, unresolved: int = 0) -> str:
    """An application with `unresolved` connections to an inventory node the
    graph does not hold, then `count` ready connections between literal
    addresses."""
    connections = "".join(
        f"  - id: u{index}\n    name: U{index}\n    source: clients\n    destination: servers\n"
        "    destination_condition: {kind: member, member: web}\n"
        for index in range(1, unresolved + 1)
    ) + "".join(
        f"  - id: c{index}\n    name: C{index}\n    source: clients\n    destination: hosts\n"
        "    destination_condition: {kind: member, member: host}\n"
        for index in range(1, count + 1)
    )
    return (
        "schema_version: 1\nid: many\nname: Many\ngroups:\n"
        "  - id: clients\n    name: Clients\n    members:\n      - id: lan\n        address: 10.9.0.0/24\n"
        "  - id: hosts\n    name: Hosts\n    members:\n      - id: host\n        address: 10.0.0.7\n"
        "  - id: servers\n    name: Servers\n    members:\n"
        "      - id: web\n        inventory: {kind: ip, uid: 'ip:10.0.0.5'}\n"
        f"connections:\n{connections}"
    )


def _not_evaluated(connection_id: str, readiness: str, reason: str, detail: str | None = None) -> dict:
    return {
        "connection_id": connection_id,
        "readiness": readiness,
        "result": None,
        "passes": [],
        "fails": [],
        "open": [],
        "missing_evidence": [],
        "display_truncated": False,
        "not_evaluated_reason": reason,
        "detail": detail,
    }


async def test_flow_verdicts_come_from_the_after_outcome_and_block_nothing(client, store, graph, monkeypatch):
    _ip_node(graph)
    calls = _evaluator(
        monkeypatch,
        lambda settings, request: {
            "outcomes": {
                "before": _outcome("holds", holds=["10.9.0.0/24"]),
                "after": _outcome("does-not-hold", fails=["10.9.0.0/25"], unknown=["10.9.0.128/25"]),
            },
            "missing_evidence": ["acl:fw1"],
        },
    )
    await login(client, "vera")
    before = copy.deepcopy(store._assessment_records)

    result = await _validate(client, yaml=YAML, evaluate=True)

    request = result["resolution"]["connections"][0]["request"]
    assert calls == [
        {
            "session_cts": 4000,
            "snapshot": 4000,
            "intents": [],
            "requirement": None,
            "request": request,
            "mode": "possible",
        }
    ]
    (flow,) = result["flows"]
    # the answer in the result vocabulary; the engine's verdict is not in the body
    verdict_result = flow.pop("result")
    assert (verdict_result["statement"], verdict_result["word"]) == ("condition-holds", "fails")
    assert flow == {
        "connection_id": "web",
        "readiness": "ready",
        "passes": [],
        "fails": ["10.9.0.0/25"],
        "open": ["10.9.0.128/25"],
        "missing_evidence": ["acl:fw1"],
        "display_truncated": False,
        "not_evaluated_reason": None,
        "detail": None,
    }
    # a flow that does not hold blocks neither a save nor the ready state
    assert result["errors"] == []
    assert result["blocking"] == []
    assert result["resolution"]["ready"] is True
    assert store._assessment_records == before
    assert await store.list_applications() == []


async def test_flows_run_only_on_request_and_only_for_ready_connections(client, store, graph, monkeypatch):
    calls = _evaluator(monkeypatch, lambda settings, request: {"outcomes": {"after": _outcome("holds")}})
    await login(client, "vera")

    unresolved = await _validate(client, yaml=YAML, evaluate=True)
    assert unresolved["flows"] == [_not_evaluated("web", "unresolved", "not-ready")]

    _ip_node(graph)
    without = await _validate(client, yaml=YAML)
    assert without["flows"] is None
    assert without["resolution"]["ready"] is True

    broken = await _validate(
        client, yaml=YAML.replace("address: 10.9.0.0/24", "address: ten-nine"), evaluate=True
    )
    assert broken["flows"] is None
    assert calls == []


async def test_a_busy_process_slot_records_capacity_busy(client, store, graph, monkeypatch):
    _ip_node(graph)
    # The evaluation reaches the process slot check of `run_isolated`, which
    # refuses before any child starts while the test holds the only slot.
    calls = _evaluator(
        monkeypatch, lambda settings, request: direct.run_isolated(settings, {"request": request})
    )
    await login(client, "vera")

    assert PROCESS_CAPACITY.acquire(blocking=False)
    try:
        result = await _validate(client, yaml=YAML, evaluate=True)
    finally:
        PROCESS_CAPACITY.release()

    assert len(calls) == 1
    assert result["flows"] == [_not_evaluated("web", "ready", "capacity-busy")]
    assert result["blocking"] == []


async def test_the_21st_ready_connection_records_over_cap(client, store, graph, monkeypatch):
    calls = _evaluator(
        monkeypatch,
        lambda settings, request: {"outcomes": {"after": _outcome("holds", holds=["10.9.0.0/24"])}},
    )
    await login(client, "vera")

    result = await _validate(client, yaml=_many_connections(21, unresolved=1), evaluate=True)

    flows = result["flows"]
    assert [flow["connection_id"] for flow in flows] == ["u1", *(f"c{index}" for index in range(1, 22))]
    # the cap counts the ready connections that stage 4 evaluates
    assert flows[0] == _not_evaluated("u1", "unresolved", "not-ready")
    assert len(calls) == 20
    assert all(flow["result"]["answer"] == "true" for flow in flows[1:21])
    assert flows[21] == _not_evaluated("c21", "ready", "over-cap")


async def test_failed_evaluations_and_the_deadline_are_recorded_per_connection(
    client, store, graph, monkeypatch
):
    answers = iter(
        [
            HTTPException(503, "Analysis time limit reached; no complete result is available."),
            {"verdict": "not-established", "stop_reason": "time-limit"},
            {"outcomes": {"after": _outcome("not-established", unknown=["10.9.0.0/24"])}},
        ]
    )

    def answer(settings, request):
        value = next(answers)
        if isinstance(value, Exception):
            raise value
        return value

    _evaluator(monkeypatch, answer)
    await login(client, "vera")

    result = await _validate(client, yaml=_many_connections(3), evaluate=True)

    assert result["flows"][:2] == [
        _not_evaluated(
            "c1",
            "ready",
            "evaluation-failed",
            "Analysis time limit reached; no complete result is available.",
        ),
        _not_evaluated(
            "c2", "ready", "evaluation-failed", "the evaluation stopped without outcomes: time-limit"
        ),
    ]
    assert result["flows"][2]["result"]["answer"] == "open"
    assert result["flows"][2]["open"] == ["10.9.0.0/24"]

    monkeypatch.setattr(validation, "FLOW_DEADLINE_S", 0.0)
    late = await _validate(client, yaml=_many_connections(2), evaluate=True)
    assert late["flows"] == [_not_evaluated(f"c{index}", "ready", "deadline") for index in (1, 2)]


async def test_any_error_of_one_connection_is_recorded_and_keeps_the_other_verdicts(
    client, store, graph, monkeypatch
):
    cut = {**_outcome("does-not-hold", fails=["10.9.0.0/25"]), "display_truncated": True}
    answers = iter(
        [
            RuntimeError("the graph driver lost its connection"),
            {"outcomes": {"after": {"holds": []}}},
            {"outcomes": {"after": cut}},
        ]
    )

    def answer(settings, request):
        value = next(answers)
        if isinstance(value, Exception):
            raise value
        return value

    _evaluator(monkeypatch, answer)
    await login(client, "vera")

    result = await _validate(client, yaml=_many_connections(3), evaluate=True)

    assert result["flows"][:2] == [
        _not_evaluated(
            "c1", "ready", "evaluation-failed", "the evaluation raised RuntimeError; see the server log"
        ),
        _not_evaluated(
            "c2", "ready", "evaluation-failed", "the evaluation answered an outcome without a result"
        ),
    ]
    assert (result["flows"][2]["result"]["answer"], result["flows"][2]["display_truncated"]) == (
        "false",
        True,
    )
    assert "graph driver" not in str(result)


async def test_validation_resolves_in_a_read_session(client, store, graph, monkeypatch):
    modes: list[str | None] = []

    @contextmanager
    def recording_session(settings, **kwargs):
        modes.append(kwargs.get("access_mode"))
        yield graph

    monkeypatch.setattr(db, "session", recording_session)
    await login(client, "vera")

    await _validate(client, yaml=YAML)

    assert modes == ["READ"]
