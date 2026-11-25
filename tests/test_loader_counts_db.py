"""The loader's created counts against a real Neo4j (core/loader.py).

Opt-in, like tests/test_integration_db.py: set NEO4J_TEST_URI (+
NEO4J_TEST_PASSWORD, optionally NEO4J_TEST_USER / NEO4J_TEST_DATABASE) to a
scratch database. The test deletes the fixture scope before and after it runs.

    NEO4J_TEST_URI=bolt://localhost:7699 NEO4J_TEST_PASSWORD=... pytest -m db
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hst.core import db as dbmod
from hst.core.config import Settings
from hst.core.fixtures import load_fixture
from hst.core.loader import load

FIXTURE = Path(__file__).parents[1] / "fixtures" / "mini-dc.yaml"
URI = os.environ.get("NEO4J_TEST_URI")

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]


@pytest.fixture()
def session():
    from neo4j import GraphDatabase

    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}). This test deletes data in "
            "the fixture scope. Point it at a scratch database.",
            returncode=2,
        )
    driver = GraphDatabase.driver(
        URI,
        auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"]),
    )
    try:
        with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
            dbmod.init_db(s)
            _cleanup(s)
            yield s
            _cleanup(s)
    finally:
        driver.close()


def _cleanup(s) -> None:
    s.run("MATCH (n:Obj) WHERE n._scope IN ['fixture:mini-dc', 'meta:runs'] DETACH DELETE n").consume()


def test_a_second_load_into_the_same_cycle_creates_nothing(session):
    batch = load_fixture(FIXTURE)
    cts = 1_000_000_000_000

    first = load(session, batch, ts_ms=cts, run_id="counts-run-0", collection_ts=cts)
    assert first.rels_dropped_missing_endpoint == 0
    assert first.nodes_upserted == first.nodes_created == len(batch.nodes)
    assert first.rels_upserted == first.rels_created == len(batch.rels)

    again = load(session, batch, ts_ms=cts + 1, run_id="counts-run-1", collection_ts=cts)
    assert again.rels_dropped_missing_endpoint == 0
    assert (again.nodes_upserted, again.nodes_created) == (len(batch.nodes), 0)
    assert (again.rels_upserted, again.rels_created) == (len(batch.rels), 0)

    stamped = session.run(
        "MATCH (:Obj {collection_ts: $cts})-[r]->(:Obj {collection_ts: $cts}) "
        "WHERE r._scope = $scope RETURN count(r) AS n, collect(DISTINCT r.collected_at) AS at",
        cts=cts,
        scope=batch.scope,
    ).single()
    assert stamped["n"] == len(batch.rels)
    assert stamped["at"] == [cts + 1]
