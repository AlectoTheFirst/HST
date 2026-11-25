"""The inventory reads of a Business Application against a real Neo4j: the
resolution and `INVENTORY_QUERY` (applications/inventory_graph.py) through
GET .../graph and GET .../flows, and the `application-inventory` canned query
with its comma-separated `$uids`.

Opt-in like tests/test_integration_db.py: set NEO4J_TEST_URI to a scratch
database. Every object here is written at one run key, which the fixture
deletes before and after every test.
"""

from __future__ import annotations

import os
from contextlib import contextmanager

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore
from tests.test_integration_db import URI
from tests.test_integration_db import _driver as _driver

from hst.applications.models import BusinessApplicationDefinition
from hst.applications.service import save_definition
from hst.assessment import service as assessment_service
from hst.assessment.store import MemoryAssessmentStore
from hst.core import db
from hst.core import uid as uids
from hst.core.loader import load
from hst.core.model import Batch, NodeRecord, RelRecord
from hst.queries import QUERIES

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]

CTS = 3_820_000_000_000
SCOPE = "test:application-inventory"
DEVICE, BALANCER = "dev:appinv-web1", "dev:appinv-lb1"
INTERFACE = uids.interface(DEVICE, "eth0")
ANCHOR = f"vrf:{DEVICE}:default"
ADDRESS = uids.ip(ANCHOR, "10.70.0.5")
PREFIX = uids.prefix(ANCHOR, "10.70.0.0/24")
VIP = uids.ip(ANCHOR, "10.70.0.100")
SERVICE, GROUP = "vs:appinv-shop", "rg:appinv-lb"
REFERENCE = {
    "snapshot": str(CTS),
    "manifest_sha256": "a" * 64,
    "estate": "test",
    "observation_floor_ms": None,
}


def batch() -> Batch:
    """A web server with an address in a prefix, and a load balancer pair
    whose virtual service owns a VIP in the same prefix."""
    return Batch(
        source="appinv",
        scope=SCOPE,
        nodes=[
            NodeRecord(label="Device", uid=DEVICE, props={"hostname": "appinv-web1", "role": "server"}),
            NodeRecord(label="Interface", uid=INTERFACE, props={"name": "eth0"}),
            NodeRecord(label="IpAddress", uid=ADDRESS, props={"ip": "10.70.0.5", "af": 4, "anchor": ANCHOR}),
            NodeRecord(label="Prefix", uid=PREFIX, props={"cidr": "10.70.0.0/24", "af": 4, "anchor": ANCHOR}),
            NodeRecord(
                label="Device", uid=BALANCER, props={"hostname": "appinv-lb1", "role": "load-balancer"}
            ),
            NodeRecord(label="RedundancyGroup", uid=GROUP, props={"name": "appinv-lb"}),
            NodeRecord(
                label="VirtualService",
                uid=SERVICE,
                props={"name": "shop-https", "vip": "10.70.0.100", "port": 443, "proto": "tcp", "kind": "lb"},
            ),
            NodeRecord(label="IpAddress", uid=VIP, props={"ip": "10.70.0.100", "af": 4, "anchor": ANCHOR}),
        ],
        rels=[
            RelRecord(type="ON", start=["Interface", INTERFACE], end=["Device", DEVICE]),
            RelRecord(type="HAS_IP", start=["Interface", INTERFACE], end=["IpAddress", ADDRESS]),
            RelRecord(type="IN", start=["IpAddress", ADDRESS], end=["Prefix", PREFIX]),
            RelRecord(type="IN", start=["IpAddress", VIP], end=["Prefix", PREFIX]),
            RelRecord(type="MEMBER_OF", start=["Device", BALANCER], end=["RedundancyGroup", GROUP]),
            RelRecord(type="ON", start=["VirtualService", SERVICE], end=["RedundancyGroup", GROUP]),
            RelRecord(type="VIP", start=["VirtualService", SERVICE], end=["IpAddress", VIP]),
        ],
    )


DEFINITION = {
    "id": "appinv",
    "name": "Inventory",
    "groups": [
        {"id": "clients", "name": "Clients", "members": [{"id": "lan", "address": "10.9.0.0/24"}]},
        {
            "id": "servers",
            "name": "Servers",
            "members": [
                {"id": "web", "inventory": {"kind": "ip", "uid": ADDRESS}},
                {"id": "vip", "inventory": {"kind": "ip", "uid": VIP}},
                {"id": "net", "inventory": {"kind": "network", "uid": PREFIX}},
            ],
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
            "destination_condition": {"kind": "member", "member": "web"},
        }
    ],
    "services": [{"id": "front", "name": "Front", "connection_ids": ["web"]}],
}


class ApplicationFakeStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return ApplicationFakeStore()


@pytest.fixture
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        _cleanup(s)
        load(s, batch(), ts_ms=CTS, collection_ts=CTS, run_id="application-inventory")
        yield s
        _cleanup(s)


def _cleanup(s) -> None:
    s.run("MATCH (n:Obj) WHERE n.collection_ts = $cts DETACH DELETE n", cts=CTS).consume()
    s.run("MATCH (r:CollectionRun) WHERE r.snapshot_ts = $cts DETACH DELETE r", cts=CTS).consume()


@pytest.fixture
def pinned(session, monkeypatch):
    """The routes' READ sessions are the test session at the loaded run."""

    @contextmanager
    def opened(settings, **kwargs):
        yield session

    monkeypatch.setattr(db, "session", opened)
    monkeypatch.setattr(assessment_service, "snapshot_reference", lambda settings, value: REFERENCE)
    return session


async def _saved(store):
    await save_definition(
        store, BusinessApplicationDefinition.model_validate(DEFINITION), expected_revision=0, actor=1
    )


async def test_the_graph_route_reads_the_members_their_devices_and_the_load_balancer(client, store, pinned):
    await _saved(store)
    await login(client, "vera")

    response = await client.get(f"/api/business-applications/appinv/graph?snapshot={CTS}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["issues"] == []
    nodes = {node["id"]: node for node in body["nodes"]}
    assert nodes[ADDRESS]["labels"][0] == "IpAddress"
    assert nodes[PREFIX]["labels"][0] == "Prefix"
    assert nodes[DEVICE]["properties"]["hostname"] == "appinv-web1"
    assert nodes[SERVICE]["properties"]["vip"] == "10.70.0.100"
    edges = {(rel["start"], rel["type"], rel["end"]) for rel in body["relationships"]}
    assert {
        ("group:servers", "MEMBER", ADDRESS),
        ("group:servers", "MEMBER", VIP),
        ("group:servers", "MEMBER", PREFIX),
        (INTERFACE, "HAS_IP", ADDRESS),
        (INTERFACE, "ON", DEVICE),
        (ADDRESS, "IN", PREFIX),
        (SERVICE, "VIP", VIP),
        (SERVICE, "ON", GROUP),
        (BALANCER, "MEMBER_OF", GROUP),
    } <= edges
    assert body["library_query"]["params"]["uids"] == ",".join(sorted([ADDRESS, PREFIX, VIP]))


async def test_the_flows_route_anchors_each_endpoint_to_its_devices(client, store, pinned):
    await _saved(store)
    await login(client, "vera")

    response = await client.get(f"/api/business-applications/appinv/flows?snapshot={CTS}")

    assert response.status_code == 200, response.text
    (web,) = response.json()["connections"]
    assert web["readiness"] == "ready"
    # nothing was evaluated, so nothing is shown as a success
    assert web["state"] == "not-evaluated"
    devices = {item["member"]: item["devices"] for item in web["endpoints"]["destination"]}
    assert devices == {"web": [DEVICE], "vip": [BALANCER], "net": []}


def test_the_application_inventory_query_takes_comma_separated_uids(session):
    cypher = next(q for q in QUERIES if q["key"] == "application-inventory")["cypher"]

    rows = session.run(cypher, uids=f" {ADDRESS}, {VIP},,{PREFIX} ", snap=CTS).data()

    by_uid = {row["uid"]: row for row in rows}
    assert sorted(by_uid) == sorted([ADDRESS, VIP, PREFIX])
    assert by_uid[ADDRESS]["kind"] == "IpAddress"
    assert by_uid[ADDRESS]["devices"] == ["appinv-web1"]
    assert "10.70.0.0/24" in by_uid[ADDRESS]["related"]
    assert by_uid[PREFIX]["kind"] == "Prefix"
    assert session.run(cypher, uids="", snap=CTS).data() == []


def test_a_device_reference_binds_no_address_of_its_interfaces(session):
    from tests.test_business_applications import one_connection_definition

    from hst.applications.models import InventoryReference
    from hst.applications.resolution import GraphInventoryReader, resolve_application

    reader = GraphInventoryReader(session, CTS)
    (interface,) = reader.resolve(InventoryReference(kind="interface", uid=INTERFACE), REFERENCE)
    assert [binding.address for binding in interface.addresses] == ["10.70.0.5"]
    (device,) = reader.resolve(InventoryReference(kind="device", uid=DEVICE), REFERENCE)
    assert device.kind == "device"
    assert device.addresses == ()
    (prefix,) = reader.resolve(InventoryReference(kind="network", uid=PREFIX), REFERENCE)
    assert [binding.address for binding in prefix.addresses] == ["10.70.0.0/24"]

    result = resolve_application(
        one_connection_definition("device", DEVICE), revision=1, snapshot=REFERENCE, reader=reader
    )

    assert result["groups"]["servers"]["web"]["bindings"] == []
    assert {issue["code"] for issue in result["issues"]} == {
        "inventory-address-unavailable",
        "destination-empty",
    }
    assert result["connections"][0]["request"] is None
