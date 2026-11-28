"""The interface search of one device (assessment/discovery.py) against a real Neo4j.

Opt-in like tests/test_search_db.py: set NEO4J_TEST_URI to a scratch database.
The fixture deletes the runs of this suite before and after every test.
"""

from __future__ import annotations

import os

import pytest

from hst.assessment import discovery
from hst.core import db as dbmod
from hst.core import uid
from hst.core.config import Settings
from hst.core.loader import load
from hst.core.model import Batch, NodeRecord, RelRecord
from hst.path.session import CycleSession

URI = os.environ.get("NEO4J_TEST_URI")

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]

OLD, RUN = 7_330_000_001_000, 7_330_000_002_000
KEYS = [OLD, RUN]
R1, R2 = "dev:disc-r1", "dev:disc-r2"


def _refuse_if_live() -> None:
    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}). This suite deletes data. "
            f"Point it at a scratch database.",
            returncode=2,
        )


@pytest.fixture(scope="module")
def _driver():
    from neo4j import GraphDatabase

    _refuse_if_live()
    driver = GraphDatabase.driver(
        URI,
        auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"]),
    )
    with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        dbmod.init_db(s)
    yield driver
    driver.close()


def _cleanup(s) -> None:
    s.run("MATCH (n:Obj) WHERE n.collection_ts IN $keys DETACH DELETE n", keys=KEYS).consume()
    s.run("MATCH (r:CollectionRun) WHERE r.snapshot_ts IN $keys DETACH DELETE r", keys=KEYS).consume()


def _load(s, cts: int, names: dict[str, list[str]]) -> None:
    nodes, rels = [], []
    for device, interfaces in names.items():
        nodes.append(NodeRecord(label="Device", uid=device, props={"role": "router", "hostname": device[4:]}))
        for name in interfaces:
            interface = uid.interface(device, name)
            nodes.append(NodeRecord(label="Interface", uid=interface, props={"name": name}))
            rels.append(RelRecord(type="ON", start=["Interface", interface], end=["Device", device]))
    manifest = load(
        s, Batch(source="disc", scope="cli:disc", nodes=nodes, rels=rels), ts_ms=cts, collection_ts=cts
    )
    assert manifest.rels_dropped_missing_endpoint == 0, manifest.errors


@pytest.fixture()
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        _cleanup(s)
        _load(s, OLD, {R1: ["eth0", "eth9"], R2: ["eth0"]})
        _load(s, RUN, {R1: ["eth0", "eth0.10", "lo"], R2: ["eth0", "eth1"]})
        yield s
        _cleanup(s)


def _names(session, cts: int, device: str, q: str = "") -> list[str]:
    found = discovery._read_options(
        CycleSession(session, cts), ["interface"], q, None, set(), 50, device=device
    )
    return [item["name"] for item in found["items"]]


def test_the_search_reads_the_interfaces_of_the_device_at_the_run(session):
    assert _names(session, RUN, R1) == ["eth0", "eth0.10", "lo"]
    assert _names(session, RUN, R2) == ["eth0", "eth1"]
    assert _names(session, OLD, R1) == ["eth0", "eth9"]


def test_the_search_text_matches_the_interface_name(session):
    assert _names(session, RUN, R1, "ETH0.") == ["eth0.10"]
    assert _names(session, RUN, "dev:disc-missing") == []


def test_an_interface_of_the_device_has_its_owner(session):
    found = discovery._read_options(
        CycleSession(session, RUN), ["interface"], "lo", None, set(), 50, device=R1
    )
    assert [(item["uid"], item["device_uid"]) for item in found["items"]] == [(uid.interface(R1, "lo"), R1)]
