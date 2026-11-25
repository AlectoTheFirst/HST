"""Release scenarios Protected change and Service-free simulation, with the
engines not stubbed.

A simulation session is saved with `analysis_sessions.save_session` and queued
with `run_session` (the functions POST /api/analysis-sessions and POST
.../runs call), claimed from the store, executed by `assessment.service.execute`
(the worker's entry, which hands it to `execute_simulation_job`), finished, and
read back with `_present` (what GET /api/analysis-sessions/{id} answers). The
overlay simulation (`fw_overlay_read.simulate_change`, tracing each flow with
`path.trace`) and each protection's evaluation (`evaluation.evaluate_change`,
the `hst.impact.evaluate` engine) run unchanged. Only the graph is
synthetic: the Neo4j session, the snapshot resolution and `path._read` answer
from the scripted estate of tests/test_impact_evaluate.py, wired as
tests/app/test_impact_api.py wires the evaluate route, with a firewall on R1.
"""

from __future__ import annotations

import json
from contextlib import contextmanager

import pytest
import tests.test_impact_evaluate as evfix
from tests.app.fakes import FakeStore
from tests.app.test_impact_api import _FakeGraphSession, _wire
from tests.test_path_trace import GW, _route, _src_row

from hst import path as pathmod
from hst.analysis.contracts import SimulationAnalysisInput
from hst.app import fw_overlay_read
from hst.app.routes import analysis_sessions
from hst.applications.models import BusinessApplicationDefinition
from hst.applications.resolution import StaticInventoryReader, resolve_application
from hst.applications.yaml_format import definition_digest, normalized_document
from hst.assessment import service as assessment_service
from hst.assessment.store import MemoryAssessmentStore
from hst.core import Settings
from hst.core.snapshot import Snapshot
from hst.path.session import GATEWAYS

REFERENCE = {"snapshot": "2000", "manifest_sha256": "a" * 64, "estate": "test", "observation_floor_ms": None}
CLIENTS = "10.0.0.0/24"
FIREWALL_CHANGE = {"kind": "fw_rule.remove", "params": {"rulebase": "rb:r1", "rule": "deny-8443"}}


class SessionStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def estate(monkeypatch):
    """R1's rulebase rb:r1 drops tcp/8443 to the application and accepts the
    rest; the change removes that rule."""
    graph = evfix.Graph()
    evfix._firewall(graph, evfix.R1, "rb:r1", [evfix._deny(evfix.APP, uid="deny-8443", port="8443")])
    # the tracer's view of R1: the clients' gateway and the route to the application
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("203.0.113.0/24", egress="eth1", next_hop="10.0.1.2")]}
    session = _FakeGraphSession()
    _wire(monkeypatch, graph, session=session)
    scripted = pathmod._read

    def read(session, query, **params):
        if query == fw_overlay_read._RULEBASE_DEVICES:
            return [{"uid": dev} for dev, rb in graph.rb_by_dev.items() if rb["rb_uid"] == params["rb"]]
        if query == GATEWAYS:
            return [dict(GW)]
        return scripted(session, query, **params)

    monkeypatch.setattr(pathmod, "_read", read)

    @contextmanager
    def db_session(_settings, **kwargs):
        yield session

    monkeypatch.setattr(analysis_sessions.db, "session", db_session)
    monkeypatch.setattr(
        analysis_sessions.snapshotmod, "resolve", lambda _session, settings, cts: Snapshot(int(cts), settings)
    )
    monkeypatch.setattr(
        assessment_service, "snapshot_reference", lambda settings, value=None: dict(REFERENCE)
    )
    monkeypatch.setattr(assessment_service, "engine_version", lambda settings: "engine-test")
    return Settings(_env_file=None)


@pytest.fixture
def store():
    return SessionStore()


def _connection(identifier: str, port: int) -> dict:
    return {
        "id": identifier,
        "name": identifier,
        "source": "clients",
        "destination": "app",
        "protocol": "tcp",
        "destination_ports": [port],
        "destination_condition": {"kind": "member", "member": "app"},
    }


async def _checkout(store) -> tuple[dict, dict]:
    """A Business Application with two explicit connections of one service,
    committed and resolved at the pinned snapshot."""
    definition = BusinessApplicationDefinition.model_validate(
        {
            "id": "checkout",
            "name": "Checkout",
            "groups": [
                {"id": "clients", "name": "Clients", "members": [{"id": "clients", "address": CLIENTS}]},
                {"id": "app", "name": "App", "members": [{"id": "app", "address": evfix.APP}]},
            ],
            "connections": [_connection("https", 443), _connection("admin", 8443)],
            "services": [{"id": "storefront", "name": "Storefront", "connection_ids": ["https", "admin"]}],
        }
    )
    saved = await store.create_application_revision(
        definition=normalized_document(definition),
        digest=definition_digest(definition),
        created_by=1,
        expected_revision=0,
    )
    resolution = resolve_application(
        definition, revision=saved.revision, snapshot=dict(REFERENCE), reader=StaticInventoryReader({})
    )
    assert resolution["ready"] is True, resolution["issues"]
    await store.save_application_resolution(resolution)
    application = {"id": "checkout", "revision": saved.revision, "digest": saved.digest}
    return application, resolution


def _application_protection(application: dict, resolution: dict, connection_id: str, desired: str) -> dict:
    return {
        "kind": "application_connection",
        "reference": {"application": application, "service_id": "storefront", "connection_id": connection_id},
        "resolved_scope_digest": resolution["digest"],
        "desired": desired,
    }


async def _save_run_reopen(store, settings, title: str, value: dict) -> tuple[dict, dict]:
    """Save the session, queue its run, execute the claimed run in the worker's
    entry, finish it, and read the session back."""
    body = analysis_sessions.CreateSession(title=title, input=value)
    created = await analysis_sessions.save_session(store, settings, body, 2)
    assert created["definition"]["runs"] == []
    queued = await analysis_sessions.run_session(
        store,
        settings,
        created["id"],
        analysis_sessions.ExecuteSession(session_revision=1, input_digest=created["input_digest"]),
        2,
    )
    claimed = await store.claim_analysis("release-scenarios")
    assert claimed is not None and claimed.kind == "simulation"
    result = assessment_service.execute(settings, claimed.inputs)
    assert await store.finish_analysis(claimed.id, claimed.lease_token, result=result)
    record = await store.get_analysis_session(created["id"])
    return queued, await analysis_sessions._present(store, record)


def _verdicts(entry: dict) -> tuple[str, str]:
    """A protection's answer before and after the change."""
    outcomes = entry["result"]["outcomes"]
    return outcomes["before"]["result"]["answer"], outcomes["after"]["result"]["answer"]


def _snapshot() -> dict:
    return {key: REFERENCE[key] for key in ("snapshot", "manifest_sha256", "estate")}


def _flow(port: int) -> dict:
    return {"src": "10.0.0.5", "dst": evfix.APP, "proto": "tcp", "port": port}


def _flow_result(simulation: dict, port: int) -> dict:
    (flow,) = [item for item in simulation["flows"] if item["flow"]["port"] == port]
    return flow


UNSERVED_SOURCE = {
    "kind": "inline",
    "name": "Unserved clients",
    "desired": "holds",
    "request": {
        "name": "Unserved clients",
        "destination": "app",
        # no interface of the estate serves these sources
        "sources": ["10.9.0.0/24"],
        "members": [{"name": "app", "addresses": [evfix.APP]}],
        "condition": {"kind": "member", "member": "app"},
        "proto": "tcp",
        "port": "443",
    },
}


async def test_protected_change_reports_desired_protected_outcomes_and_unresolved_evidence_apart(
    estate, store
):
    """Protected change: a firewall change simulated with two selected
    application protections and one standalone protection. Each protection
    keeps its desired state beside its own before/after outcome, and the one
    the evidence cannot decide is reported open with its missing evidence,
    not folded into a pass or a fail."""
    application, resolution = await _checkout(store)
    value = {
        "kind": "simulation",
        "snapshot": _snapshot(),
        "changes": [FIREWALL_CHANGE],
        "scope": {"flows": [_flow(8443)]},
        "protected": [
            _application_protection(application, resolution, "https", "holds"),
            _application_protection(application, resolution, "admin", "isolated"),
            UNSERVED_SOURCE,
        ],
    }
    queued, reopened = await _save_run_reopen(store, estate, "Remove the 8443 deny", value)
    assert queued["definition"]["runs"][0]["execution"] == "queued"
    (run,) = reopened["definition"]["runs"]
    assert run["execution"] == "completed"

    # the change itself: the 8443 flow is blocked by rb:r1 rule 1 before and
    # accepted after, on the changed device
    simulation = reopened["results"]["simulation"]
    assert simulation["changed_devices"] == [evfix.R1]
    flow = _flow_result(simulation, 8443)
    assert flow["before"]["blocked"] is True and flow["after"]["blocked"] is False
    assert flow["before"]["decided_by"] == ["rb:r1 (checkpoint) drop by rule 1"]
    assert flow["crosses_a_changed_device"] is True

    https, admin, unserved = reopened["results"]["protected"]
    # each protection is bound to what was selected, with its desired state
    assert https["reference"]["reference"] == {
        "application": application,
        "service_id": "storefront",
        "connection_id": "https",
    }
    assert https["reference"]["resolved_scope_digest"] == resolution["digest"]
    assert admin["reference"]["reference"]["connection_id"] == "admin"
    assert unserved["reference"]["kind"] == "inline"
    assert [item["desired"] for item in (https, admin, unserved)] == ["holds", "isolated", "holds"]
    # the request each application protection was evaluated with is the one
    # its connection resolved to
    resolved = {item["id"]: item["request"] for item in resolution["connections"]}
    assert https["result"]["request"]["name"] == resolved["https"]["name"]
    assert admin["result"]["request"]["members"][0]["addresses"] == ["203.0.113.10/32"]

    # desired holds, and it holds on both sides
    assert _verdicts(https) == ("true", "true")
    assert https["result"]["missing_evidence"] == []
    # desired isolated: isolated before, reachable after
    assert admin["result"]["outcomes"]["before"]["isolated"] is True
    assert admin["result"]["outcomes"]["after"]["isolated"] is False
    assert _verdicts(admin) == ("false", "true")
    assert admin["result"]["missing_evidence"] == []
    # unresolved evidence: open on both sides, with what is missing, and
    # neither passing nor failing
    assert _verdicts(unserved) == ("open", "open")
    after = unserved["result"]["outcomes"]["after"]
    assert after["open"] == ["10.9.0.0/24"] and after["passes"] == [] and after["fails"] == []
    assert unserved["result"]["missing_evidence"] == ["no interface in the model serves the source addresses"]


async def test_service_free_simulation_saves_runs_and_reopens_without_a_service(estate, store):
    """Service-free simulation: a supported firewall change with an explicit
    flow scope is saved, run by the real engines and reopened. No Business
    Application or service exists before or after, and none is referenced."""
    value = {
        "kind": "simulation",
        "snapshot": _snapshot(),
        "changes": [FIREWALL_CHANGE],
        "scope": {"flows": [_flow(8443), _flow(443)], "sites": []},
    }
    queued, reopened = await _save_run_reopen(store, estate, "Remove the 8443 deny", value)
    assert await store.list_applications() == []

    simulation = reopened["results"]["simulation"]
    opened = _flow_result(simulation, 8443)
    assert opened["before"]["blocked"] is True and opened["after"]["blocked"] is False
    assert opened["after"]["decided_by"] == ["rb:r1 (checkpoint) accept by default-action"]
    unchanged = _flow_result(simulation, 443)
    assert unchanged["before"]["blocked"] is False and unchanged["after"]["blocked"] is False
    assert unchanged["result_changed"] is False
    assert simulation["results_changed"] == 1
    assert reopened["results"]["protected"] == []

    # reopened: the reviewed input as saved, and the result of the run that was executed
    assert reopened["definition"]["input"] == SimulationAnalysisInput.model_validate(value).model_dump(
        mode="json"
    )
    assert reopened["input_digest"] == queued["input_digest"]
    (summary,) = reopened["definition"]["runs"]
    stored = await store.get_analysis_run(summary["id"])
    assert stored.result["simulation"] == simulation
    again = await analysis_sessions._present(store, await store.get_analysis_session(reopened["id"], 2))
    assert again["results"]["simulation"] == simulation

    # nothing in the input or the result names an application or a service
    text = json.dumps({"definition": reopened["definition"], "results": reopened["results"]})
    for key in ('"service_id"', '"application"', '"application_connection"'):
        assert key not in text
