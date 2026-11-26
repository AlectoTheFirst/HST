"""Release scenarios Protected change and Service-free simulation through HTTP
against a real Neo4j.

fixtures/path-a.yaml and the VyOS half of path A load into one run of the
NEO4J_TEST_URI database (tests/test_integration_db.py `_load_path_a`), and an
evidence manifest is written for that run. The app reads Neo4j through its own
settings. The routes save and resolve the application, save the session and
queue its run. `AnalysisWorker.run_once` claims the run and executes it in a
child process. GET /api/analysis-sessions/{id} reads the result.

The change adds a drop rule for 10.0.30.10 at position 1 of the Check Point
rulebase on dev:patha-cp01. The flow 10.20.1.50 to 10.0.30.10 tcp/443 crosses
that rulebase.
"""

from __future__ import annotations

import os

import httpx
import pytest
from tests.app.conftest import PUBLIC_URL, login
from tests.app.fakes import FakeStore
from tests.test_integration_db import URI, _load_path_a
from tests.test_integration_db import _driver as _driver
from tests.test_integration_db import session as session

from hst.app.crypto import generate_key
from hst.app.main import create_app
from hst.assessment.jobs import AnalysisWorker
from hst.assessment.store import MemoryAssessmentStore
from hst.core import Settings, manifest
from hst.core.model import SectionOutcome

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]

TS = 8_130_000_000_000
CLIENT = "10.20.1.50"
SERVER = "10.0.30.10"
DROP = {
    "kind": "fw_rule.add",
    "params": {
        "rulebase": "cp:patha:smc:pkg-dc-access",
        "position": 1,
        "action": "drop",
        "source": "any",
        "destination": [f"{SERVER}/32"],
    },
}
FLOW = {"src": CLIENT, "dst": SERVER, "proto": "tcp", "port": 443}


class SessionStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def settings(tmp_path):
    return Settings(
        _env_file=None,
        hst_secret_key=generate_key(),
        HST_PUBLIC_URL=PUBLIC_URL,
        hst_data_dir=tmp_path,
        neo4j_uri=URI,
        neo4j_user=os.environ.get("NEO4J_TEST_USER", "neo4j"),
        neo4j_password=os.environ["NEO4J_TEST_PASSWORD"],
        neo4j_database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j"),
    )


# The device, its host, its source and the policy sections that
# path/gates/coverage.py `_POLICY_SECTIONS` requires for the source type.
DEVICES = [
    ("dev:patha-edge", "patha-edge", "patha-vyos", "vyos", ["config"]),
    ("dev:patha-cp01", "patha-cp01", "patha-checkpoint", "checkpoint", ["access", "nat"]),
    ("dev:patha-ns01", "patha-ns01", "patha-netscaler", "netscaler", []),
]


@pytest.fixture
def path_a(session, settings):
    """Path A loaded at TS, with an evidence manifest that records each device
    of the run as collected with complete policy sections."""
    _load_path_a(session, TS)
    record = manifest.build(
        settings=settings,
        snapshot_key=TS,
        kind="full",
        parent=None,
        sources=[
            manifest.SourceEntry(name=source, type=kind, status="ok", config_sha256="0" * 64)
            for _uid, _host, source, kind, _sections in DEVICES
        ],
        devices=[
            manifest.DeviceEntry(
                source=source,
                host=host,
                outcome="collected",
                fetch_started_ms=TS,
                fetch_finished_ms=TS,
                sections={name: SectionOutcome(status="ok") for name in sections},
                expected_sections=sections,
                device_uids=[uid],
            )
            for uid, host, source, _kind, sections in DEVICES
        ],
        files=[],
        delta=manifest.GraphDelta(),
    )
    manifest.write(settings, record, manifest.signer_for(settings))
    return str(TS)


@pytest.fixture
async def store(path_a):
    store = SessionStore()
    await store.create_user("otto", _password_hash(), "operator")
    return store


@pytest.fixture
async def client(settings, store):
    app = create_app(settings=settings, store=store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_URL, headers={"X-HST-CSRF": "1"}) as c:
        await login(c, "otto")
        yield c


def _password_hash() -> str:
    from tests.app.conftest import PASSWORD

    from hst.app.security import hash_password

    return hash_password(PASSWORD)


CHECKOUT = {
    "id": "checkout",
    "name": "Checkout",
    "groups": [
        {"id": "clients", "name": "Clients", "members": [{"id": "clients", "address": "10.20.1.0/24"}]},
        {"id": "web", "name": "Web", "members": [{"id": "web", "address": SERVER}]},
    ],
    "connections": [
        {
            "id": "https",
            "name": "https",
            "source": "clients",
            "destination": "web",
            "protocol": "tcp",
            "destination_ports": [443],
            "destination_condition": {"kind": "member", "member": "web"},
        }
    ],
    "services": [{"id": "storefront", "name": "Storefront", "connection_ids": ["https"]}],
}

UNSERVED = {
    "kind": "inline",
    "name": "Unserved clients",
    "desired": "holds",
    "request": {
        "name": "Unserved clients",
        "destination": "web",
        "sources": ["10.9.0.0/24"],
        "members": [{"name": "web", "addresses": [SERVER]}],
        "condition": {"kind": "member", "member": "web"},
        "proto": "tcp",
        "port": "443",
    },
}


async def _reference(client) -> dict:
    r = await client.get("/api/analysis-snapshot", params={"snapshot": str(TS)})
    assert r.status_code == 200, r.text
    return r.json()


async def _save_run_reopen(client, store, settings, title: str, value: dict) -> dict:
    """POST the session and its run, let the worker execute the run, and GET
    the session."""
    r = await client.post("/api/analysis-sessions", json={"title": title, "input": value})
    assert r.status_code == 201, r.text
    created = r.json()
    r = await client.post(
        f"/api/analysis-sessions/{created['id']}/runs",
        json={"session_revision": 1, "input_digest": created["input_digest"]},
    )
    assert r.status_code == 202, r.text
    assert r.json()["definition"]["runs"][0]["execution"] == "queued"

    worker = AnalysisWorker(store, settings, poll_s=0.05, lease_seconds=60)
    assert await worker.run_once() is True

    r = await client.get(f"/api/analysis-sessions/{created['id']}")
    assert r.status_code == 200, r.text
    reopened = r.json()
    (run,) = reopened["definition"]["runs"]
    assert run["execution"] == "completed", run
    return reopened


def _flow(simulation: dict) -> dict:
    (flow,) = simulation["flows"]
    return flow


async def test_protected_change_through_http_keeps_each_protection_open_with_its_missing_evidence(
    client, store, settings
):
    reference = await _reference(client)
    assert reference["snapshot"] == str(TS)

    r = await client.post("/api/business-applications", json={"definition": CHECKOUT, "expected_revision": 0})
    assert r.status_code == 201, r.text
    saved = r.json()
    r = await client.post(
        "/api/business-applications/checkout/resolve",
        json={"snapshot": str(TS), "revision": saved["revision"]},
    )
    assert r.status_code == 200, r.text
    resolution = r.json()
    assert resolution["ready"] is True, resolution["issues"]

    application = {"id": "checkout", "revision": saved["revision"], "digest": saved["digest"]}
    protection = {
        "kind": "application_connection",
        "reference": {"application": application, "service_id": "storefront", "connection_id": "https"},
        "resolved_scope_digest": resolution["digest"],
        "desired": "holds",
    }
    value = {
        "kind": "simulation",
        "snapshot": {key: reference[key] for key in ("snapshot", "manifest_sha256", "estate")},
        "changes": [DROP],
        "scope": {"flows": [FLOW]},
        "protected": [protection, UNSERVED],
    }
    reopened = await _save_run_reopen(client, store, settings, "Drop 10.0.30.10 at dc-access", value)

    simulation = reopened["results"]["simulation"]
    assert simulation["changed_devices"] == ["dev:patha-cp01"]
    flow = _flow(simulation)
    assert flow["before"]["blocked"] is False and flow["after"]["blocked"] is True
    assert flow["after"]["decided_by"] == ["dc-access (checkpoint) drop by rule 1"]

    https, unserved = reopened["results"]["protected"]
    assert https["reference"]["reference"] == {
        "application": application,
        "service_id": "storefront",
        "connection_id": "https",
    }
    assert https["reference"]["resolved_scope_digest"] == resolution["digest"]
    assert [item["desired"] for item in (https, unserved)] == ["holds", "holds"]
    # path A publishes no observed route table of the VyOS default VRF
    before, after = (https["result"]["outcomes"][side]["result"]["answer"] for side in ("before", "after"))
    assert (before, after) == ("open", "open")
    outcome = https["result"]["outcomes"]["after"]
    assert outcome["open"] == ["10.20.1.0/24"] and outcome["passes"] == [] and outcome["fails"] == []
    assert https["result"]["missing_evidence"] == [
        "baseline forwarding coverage for vrf:dev:patha-edge:default is not observed",
        "baseline forwarding observations do not cover the requested address family in "
        "vrf:dev:patha-edge:default",
    ]

    before, after = (unserved["result"]["outcomes"][side]["result"]["answer"] for side in ("before", "after"))
    assert (before, after) == ("open", "open")
    outcome = unserved["result"]["outcomes"]["after"]
    assert outcome["open"] == ["10.9.0.0/24"] and outcome["passes"] == [] and outcome["fails"] == []
    assert unserved["result"]["missing_evidence"] == ["no interface in the model serves the source addresses"]


async def test_service_free_simulation_through_http_saves_runs_and_reopens_without_a_service(
    client, store, settings
):
    reference = await _reference(client)
    value = {
        "kind": "simulation",
        "snapshot": {key: reference[key] for key in ("snapshot", "manifest_sha256", "estate")},
        "changes": [DROP],
        "scope": {"flows": [FLOW], "sites": []},
    }
    reopened = await _save_run_reopen(client, store, settings, "Drop 10.0.30.10 at dc-access", value)

    flow = _flow(reopened["results"]["simulation"])
    assert flow["before"]["blocked"] is False and flow["after"]["blocked"] is True
    assert reopened["results"]["protected"] == []
    r = await client.get("/api/business-applications")
    assert r.status_code == 200 and r.json()["applications"] == []

    r = await client.get(f"/api/analysis-sessions/{reopened['id']}")
    assert r.json()["results"]["simulation"] == reopened["results"]["simulation"]
    text = r.text
    for key in ('"service_id"', '"application"', '"application_connection"'):
        assert key not in text
